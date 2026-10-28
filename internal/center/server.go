package center

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"edr/internal/event"
	"edr/internal/requestauth"
) // Server exposes the center HTTP API.
type Server struct {
	store   *Store
	cases   *CaseStore
	actions *ActionStore
	auth    *requestauth.Authenticator
}

// NewServer builds a center server guarded by an HMAC secret.
func NewServer(store *Store, secret []byte) *Server {
	return &Server{store: store, auth: requestauth.New(secret, 60*time.Second)}
}

// WithCases attaches a case store and returns the server.
func (s *Server) WithCases(cs *CaseStore) *Server {
	s.cases = cs
	return s
}

// WithActions attaches an action store and returns the server.
func (s *Server) WithActions(as *ActionStore) *Server {
	s.actions = as
	return s
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "component": "center"})
	})
	mux.HandleFunc("/v0/center/ingest", s.ingest)
	mux.HandleFunc("/v0/center/hosts", s.hosts)
	mux.HandleFunc("/v0/center/events", s.events)
	mux.HandleFunc("/v0/center/correlations", s.correlations)
	mux.HandleFunc("/v0/center/cases", s.casesList)
	mux.HandleFunc("/v0/center/cases/", s.caseOp)
	mux.HandleFunc("/v0/center/report", s.report)
	mux.HandleFunc("/v0/center/export", s.export)
	mux.HandleFunc("/v0/center/actions", s.actionsList)
	mux.HandleFunc("/v0/center/actions/", s.actionOp)
	mux.HandleFunc("/v0/center/agent/actions", s.agentActions)
	mux.HandleFunc("/v0/center/agent/actions/result", s.agentActionResult)
	mux.HandleFunc("/v0/center/anchor", s.anchor)
	return mux
}

// anchor is the remote anchor endpoint: agents push their chain head here and
// read it back on restart, so truncation/rewrite is detectable off-host. The
// stored sequence never decreases (a lower push is ignored), and GET responses
// are HMAC-signed.
func (s *Server) anchor(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if err := s.auth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		rec, ok := s.store.LoadAnchor(host)
		if !ok {
			http.Error(w, "anchor not found", http.StatusNotFound)
			return
		}
		body, err := json.Marshal(rec)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if sig := s.auth.SignBody(body); sig != "" {
			w.Header().Set("X-EDR-Response-Signature", sig)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.auth.Authorize(r, body); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		var rec anchorRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, "bad anchor", http.StatusBadRequest)
			return
		}
		if rec.ChainID == "" || rec.Seq == 0 {
			http.Error(w, "invalid anchor", http.StatusBadRequest)
			return
		}
		if cur, ok := s.store.LoadAnchor(host); ok && cur.Seq >= rec.Seq {
			// Never lower the stored head: a compromised host must not be able
			// to mask truncation by pushing an older anchor.
			writeJSON(w, map[string]any{"ok": true, "kept": true, "seq": cur.Seq})
			return
		}
		if err := s.store.SaveAnchor(host, rec); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "seq": rec.Seq})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.auth.Authorize(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var payload struct {
		Events []event.Event `json:"events"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stored := s.store.IngestBatch(payload.Events)
	writeJSON(w, map[string]any{"received": len(payload.Events), "stored": stored})
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, s.store.Hosts())
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := s.store.Query(Filter{
		Host:        q.Get("host"),
		RuleID:      q.Get("rule_id"),
		MinSeverity: q.Get("min_severity"),
		Limit:       limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

func (s *Server) correlations(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	window := 15 * time.Minute
	if v := q.Get("window_sec"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			window = time.Duration(n) * time.Second
		}
	}
	events, err := s.store.Query(Filter{Limit: 100000})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findings := Correlate(events, window)
	if len(findings) > limit {
		findings = findings[len(findings)-limit:]
	}
	writeJSON(w, findings)
}

func (s *Server) actionsList(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "actions not configured", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if err := s.auth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, s.actions.List())
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.auth.Authorize(r, body); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		var req struct {
			Host       string `json:"host"`
			Action     string `json:"action"`
			PID        int    `json:"pid"`
			Path       string `json:"path"`
			Exe        string `json:"exe"`
			StartTicks uint64 `json:"start_ticks"`
			Reason     string `json:"reason"`
			By         string `json:"requested_by"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a, err := s.actions.Create(req.Host, req.Action, req.PID, req.Path, req.Exe, req.StartTicks, req.Reason, req.By)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, a)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) actionOp(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "actions not configured", http.StatusNotImplemented)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v0/center/actions/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		http.Error(w, "action id required", http.StatusBadRequest)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.auth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		a, ok := s.actions.Get(id)
		if !ok {
			http.Error(w, "action not found", http.StatusNotFound)
			return
		}
		writeJSON(w, a)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := s.auth.Authorize(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var req struct {
		By     string `json:"by"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &req)
	switch parts[1] {
	case "approve":
		if err := s.actions.Approve(id, req.By); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "reject":
		if err := s.actions.Reject(id, req.By, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unknown action operation", http.StatusNotFound)
		return
	}
	a, _ := s.actions.Get(id)
	writeJSON(w, a)
}

// agentActions is polled by agents for approved work addressed to them.
func (s *Server) agentActions(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "actions not configured", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	host := r.URL.Query().Get("host")
	// Sign the action body: the agent acts on it, so an on-path attacker must
	// not be able to inject a destructive action even though the request itself
	// is authenticated.
	body, err := json.Marshal(s.actions.PendingFor(host))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sig := s.auth.SignBody(body); sig != "" {
		w.Header().Set("X-EDR-Response-Signature", sig)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// agentActionResult records the outcome posted by an agent.
func (s *Server) agentActionResult(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "actions not configured", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.auth.Authorize(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var req struct {
		ID       string `json:"id"`
		Success  bool   `json:"success"`
		Enforced bool   `json:"enforced"`
		Detail   string `json:"detail"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.actions.Complete(req.ID, req.Success, req.Enforced, req.Detail); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, BuildReport(s.store, s.cases))
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	limit := 1000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := s.store.Query(Filter{Host: q.Get("host"), Limit: limit})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var lines []string
	switch format {
	case "cef":
		lines = ExportCEF(events)
	case "leef":
		lines = ExportLEEF(events)
	default:
		http.Error(w, "format must be cef or leef", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

func (s *Server) casesList(w http.ResponseWriter, r *http.Request) {
	if s.cases == nil {
		http.Error(w, "cases not configured", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if err := s.auth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, s.cases.List())
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.auth.Authorize(r, body); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		var req struct {
			Title      string   `json:"title"`
			Severity   string   `json:"severity"`
			Hosts      []string `json:"hosts"`
			Rules      []string `json:"rules"`
			Techniques []string `json:"techniques"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Title == "" {
			req.Title = "untitled case"
		}
		if req.Severity == "" {
			req.Severity = "medium"
		}
		c, err := s.cases.Create(req.Title, req.Severity, req.Hosts, req.Rules, req.Techniques)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, c)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) caseOp(w http.ResponseWriter, r *http.Request) {
	if s.cases == nil {
		http.Error(w, "cases not configured", http.StatusNotImplemented)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v0/center/cases/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		http.Error(w, "case id required", http.StatusBadRequest)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.auth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		c, ok := s.cases.Get(id)
		if !ok {
			http.Error(w, "case not found", http.StatusNotFound)
			return
		}
		writeJSON(w, c)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.auth.Authorize(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	switch parts[1] {
	case "status":
		var req struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.cases.SetStatus(id, req.Status); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "disposition":
		var req struct {
			Disposition string `json:"disposition"`
			Note        string `json:"note"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.cases.SetDisposition(id, req.Disposition, req.Note); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "note":
		var req struct {
			Author string `json:"author"`
			Text   string `json:"text"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.cases.AddNote(id, req.Author, req.Text); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unknown case operation", http.StatusNotFound)
		return
	}
	c, _ := s.cases.Get(id)
	writeJSON(w, c)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
