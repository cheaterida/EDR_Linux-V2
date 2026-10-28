// Package control exposes the agent's control plane over a Unix-domain HTTP
// socket. Access is gated by SO_PEERCRED UID allow-listing; privileged
// actions additionally require an admin token (or a root login session).
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"edr/internal/adminauth"
	"edr/internal/event"
)

const unsetLoginUID = uint32(4294967295)

type peerCred struct {
	uid uint32
	gid uint32
	pid int32
}

type credKey struct{}

// ConnContext captures SO_PEERCRED for every accepted connection.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return ctx
	}
	return context.WithValue(ctx, credKey{}, peerCred{uid: cred.Uid, gid: cred.Gid, pid: cred.Pid})
}

// Deps are the callbacks the server needs from the agent.
type Deps struct {
	AllowedUIDs       []int
	Admin             *adminauth.Auth
	EventPath         string
	Status            func() map[string]any
	PolicyInfo        func() map[string]any
	ReloadPolicy      func() error
	Shutdown          func()
	NFTRollback       func() any
	QuarantineList    func() any
	QuarantineRestore func(path string) any
	ExecuteResponse   func(action string, args map[string]any) any
}

// Server renders the control-plane handler.
type Server struct {
	deps Deps
}

// New returns a Server.
func New(deps Deps) *Server { return &Server{deps: deps} }

// Handler implements http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", s.wrap(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/v0/status", s.wrap(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.Status == nil {
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		writeJSON(w, s.deps.Status())
	}))
	mux.HandleFunc("/v0/policy", s.wrap(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.PolicyInfo == nil {
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		writeJSON(w, s.deps.PolicyInfo())
	}))
	mux.HandleFunc("/v0/events", s.wrap(func(w http.ResponseWriter, r *http.Request) {
		s.handleEvents(w, r)
	}))
	mux.HandleFunc("/v0/policy/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r, "policy-reload") {
			return
		}
		if s.deps.ReloadPolicy == nil {
			http.Error(w, "reload not supported", http.StatusNotImplemented)
			return
		}
		if err := s.deps.ReloadPolicy(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/v0/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r, "shutdown") {
			return
		}
		writeJSON(w, map[string]any{"ok": true})
		if s.deps.Shutdown != nil {
			go s.deps.Shutdown()
		}
	})
	mux.HandleFunc("/v0/quarantine/list", s.wrap(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.QuarantineList == nil {
			http.Error(w, "quarantine not configured", http.StatusNotImplemented)
			return
		}
		writeJSON(w, s.deps.QuarantineList())
	}))
	mux.HandleFunc("/v0/quarantine/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r, "enforce-toggle") {
			return
		}
		if s.deps.QuarantineRestore == nil {
			http.Error(w, "quarantine not configured", http.StatusNotImplemented)
			return
		}
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Path == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}
		writeJSON(w, s.deps.QuarantineRestore(req.Path))
	})
	mux.HandleFunc("/v0/response/nft/rollback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r, "enforce-toggle") {
			return
		}
		if s.deps.NFTRollback == nil {
			http.Error(w, "nft not configured", http.StatusNotImplemented)
			return
		}
		writeJSON(w, s.deps.NFTRollback())
	})
	mux.HandleFunc("/v0/response/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r, "enforce-toggle") {
			return
		}
		if s.deps.ExecuteResponse == nil {
			http.Error(w, "response execution not configured", http.StatusNotImplemented)
			return
		}
		var req struct {
			Action     string `json:"action"`
			PID        int    `json:"pid"`
			Path       string `json:"path"`
			RemoteAddr string `json:"remote_addr"`
			RemotePort int    `json:"remote_port"`
			Protocol   string `json:"protocol"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Action == "" {
			http.Error(w, "action required", http.StatusBadRequest)
			return
		}
		writeJSON(w, s.deps.ExecuteResponse(req.Action, map[string]any{
			"pid": req.PID, "path": req.Path,
			"remote_addr": req.RemoteAddr, "remote_port": req.RemotePort, "protocol": req.Protocol,
		}))
	})
	return mux
}

func (s *Server) wrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(w, r) {
			return
		}
		h(w, r)
	}
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	cred, ok := r.Context().Value(credKey{}).(peerCred)
	if !ok {
		http.Error(w, "no peer credentials", http.StatusForbidden)
		return false
	}
	for _, uid := range s.deps.AllowedUIDs {
		if int(cred.uid) == uid {
			return true
		}
	}
	http.Error(w, fmt.Sprintf("uid %d not authorized", cred.uid), http.StatusForbidden)
	return false
}

// requireAdmin accepts an admin token, or (fallback) a root login session.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, action string) bool {
	cred, ok := r.Context().Value(credKey{}).(peerCred)
	if !ok {
		http.Error(w, "no peer credentials", http.StatusForbidden)
		return false
	}
	token := r.Header.Get("X-EDR-Admin-Token")
	if token != "" {
		if s.deps.Admin == nil || !s.deps.Admin.Enabled() {
			http.Error(w, "admin token not configured", http.StatusServiceUnavailable)
			return false
		}
		if err := s.deps.Admin.Verify(token, action, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return false
		}
		return true
	}
	// Fallback: only a genuine root login session.
	if cred.uid == 0 && rootLoginSession(cred.pid) {
		return true
	}
	http.Error(w, "admin token or root login required", http.StatusForbidden)
	return false
}

func rootLoginSession(pid int32) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return false
	}
	return uint32(n) == 0 || uint32(n) == unsetLoginUID
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.deps.EventPath == "" {
		http.Error(w, "event log not configured", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	rule := q.Get("rule_id")
	minRank := severityRank(q.Get("min_severity"))
	subjectPID := q.Get("subject_pid")
	summary := q.Get("format") == "summary"

	events, err := readEvents(s.deps.EventPath, limit, rule, minRank, subjectPID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if summary {
		out := make([]map[string]any, 0, len(events))
		for _, e := range events {
			out = append(out, map[string]any{
				"time":     e.Time,
				"rule_id":  e.ChainRule(),
				"kind":     e.Kind.String(),
				"severity": e.Severity(),
			})
		}
		writeJSON(w, out)
		return
	}
	writeJSON(w, events)
}

func readEvents(path string, limit int, rule string, minRank int, subjectPID string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	var ring []event.Event
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if rule != "" && !ev.HasRule(rule) {
			continue
		}
		if minRank > 0 && severityRank(ev.Severity()) < minRank {
			continue
		}
		if subjectPID != "" && strconv.FormatUint(uint64(ev.PID), 10) != subjectPID {
			continue
		}
		ring = append(ring, ev)
		if len(ring) > limit {
			ring = ring[len(ring)-limit:]
		}
	}
	return ring, sc.Err()
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info", "":
		return 0
	}
	return 0
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
