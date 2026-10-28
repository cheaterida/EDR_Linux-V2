// Package supervisor is the HA quorum decider. Peers POST heartbeats; when a
// peer is reported down and is not recently alive from the supervisor's view,
// the supervisor issues a single restart intent (with a cooldown) so only one
// side acts.
package supervisor

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"edr/internal/liveness"
	"edr/internal/requestauth"
)

// HeartbeatRequest is what a peer posts.
type HeartbeatRequest struct {
	RequestID      string             `json:"request_id"`
	SentAt         time.Time          `json:"sent_at"`
	InstanceID     string             `json:"instance_id"`
	PeerInstanceID string             `json:"peer_instance_id"`
	Hostname       string             `json:"hostname,omitempty"`
	BootID         string             `json:"boot_id,omitempty"`
	Priority       int                `json:"priority"`
	PeerState      string             `json:"peer_state"`
	Local          liveness.Heartbeat `json:"local"`
}

// RestartIntent tells the caller to restart Target.
type RestartIntent struct {
	RequestID  string `json:"request_id"`
	Target     string `json:"target"`
	Generation uint64 `json:"generation"`
	Reason     string `json:"reason"`
}

// HeartbeatResponse is the supervisor's reply.
type HeartbeatResponse struct {
	OK            bool           `json:"ok"`
	Decision      string         `json:"decision"`
	RestartIntent *RestartIntent `json:"restart_intent,omitempty"`
}

// DecisionRecord is a compact audit of a decision.
type DecisionRecord struct {
	At         time.Time `json:"at"`
	InstanceID string    `json:"instance_id"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
}

// Server is the supervisor HTTP handler.
type Server struct {
	auth           *requestauth.Authenticator
	mu             sync.Mutex
	hosts          map[string]HeartbeatRequest
	lastDecisionAt map[string]time.Time
	decisions      []DecisionRecord
	decisionTTL    time.Duration
	hostStaleAfter time.Duration
	maxHistory     int
}

// Options configures the server.
type Options struct {
	Secret         []byte
	DecisionTTL    time.Duration
	HostStaleAfter time.Duration
	MaxHistory     int
}

// NewServer builds a supervisor.
func NewServer(opts Options) *Server {
	if opts.DecisionTTL <= 0 {
		opts.DecisionTTL = 30 * time.Second
	}
	if opts.HostStaleAfter <= 0 {
		opts.HostStaleAfter = 10 * time.Second
	}
	if opts.MaxHistory <= 0 {
		opts.MaxHistory = 128
	}
	return &Server{
		auth:           requestauth.New(opts.Secret, 30*time.Second),
		hosts:          map[string]HeartbeatRequest{},
		lastDecisionAt: map[string]time.Time{},
		decisionTTL:    opts.DecisionTTL,
		hostStaleAfter: opts.HostStaleAfter,
		maxHistory:     opts.MaxHistory,
	}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "component": "supervisor"})
	})
	mux.HandleFunc("/v0/supervisor/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/v0/supervisor/status", s.handleStatus)
	return mux
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
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
	var req HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.decide(req, time.Now()))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Authorize(r, nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]HeartbeatRequest, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, h)
	}
	writeJSON(w, map[string]any{"ok": true, "hosts": hosts, "decisions": s.decisions})
}

func (s *Server) decide(req HeartbeatRequest, now time.Time) HeartbeatResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	localKey := req.Hostname + "|" + req.InstanceID
	peerKey := req.Hostname + "|" + req.PeerInstanceID
	s.hosts[localKey] = req

	resp := HeartbeatResponse{OK: true}
	if req.PeerState != "down" {
		resp.Decision = "skip"
		s.audit(req, "skip", "peer_not_down", now)
		return resp
	}
	// If the supervisor recently saw the peer alive, don't act (avoid split brain).
	if peer, ok := s.hosts[peerKey]; ok && now.Sub(peer.SentAt) <= s.hostStaleAfter {
		resp.Decision = "skip"
		s.audit(req, "skip", "peer_recently_alive", now)
		return resp
	}
	decKey := localKey + "->" + peerKey
	if last, ok := s.lastDecisionAt[decKey]; ok && now.Sub(last) < s.decisionTTL {
		resp.Decision = "skip"
		s.audit(req, "skip", "decision_cooldown", now)
		return resp
	}
	s.lastDecisionAt[decKey] = now
	resp.Decision = "issue_restart_intent"
	resp.RestartIntent = &RestartIntent{
		RequestID:  "restart-" + req.InstanceID + "-" + req.PeerInstanceID,
		Target:     req.PeerInstanceID,
		Generation: req.Local.RestartGeneration + 1,
		Reason:     "peer_down_quorum",
	}
	s.audit(req, resp.Decision, "supervisor-quorum", now)
	return resp
}

func (s *Server) audit(req HeartbeatRequest, decision, reason string, now time.Time) {
	s.decisions = append(s.decisions, DecisionRecord{At: now, InstanceID: req.InstanceID, Decision: decision, Reason: reason})
	if len(s.decisions) > s.maxHistory {
		s.decisions = s.decisions[len(s.decisions)-s.maxHistory:]
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
