package center

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Orchestrated action states.
var actionStates = map[string]bool{
	"pending": true, "approved": true, "rejected": true,
	"dispatched": true, "completed": true, "failed": true,
}

// allowedActions is the closed enumeration the center may ever dispatch. The
// center cannot send arbitrary commands — only these response primitives.
var allowedActions = map[string]bool{
	"kill": true, "kill_tree": true, "quarantine": true,
	"fix_permissions": true, "process_suspend": true,
}

// ActionRequest is a queued response action for a specific host.
type ActionRequest struct {
	ID          string      `json:"id"`
	Host        string      `json:"host"`
	Action      string      `json:"action"`
	PID         int         `json:"pid,omitempty"`
	Path        string      `json:"path,omitempty"`
	Exe         string      `json:"exe,omitempty"`
	StartTicks  uint64      `json:"start_ticks,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	State       string      `json:"state"`
	RequestedBy string      `json:"requested_by,omitempty"`
	ApprovedBy  string      `json:"approved_by,omitempty"`
	Result      string      `json:"result,omitempty"`
	Enforced    bool        `json:"enforced,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Timeline    []CaseEvent `json:"timeline"`
}

// ActionStore persists action requests as one JSON file each.
type ActionStore struct {
	mu      sync.Mutex
	dir     string
	actions map[string]*ActionRequest
}

// OpenActions loads (or creates) the action store at dir/actions.
func OpenActions(dir string) (*ActionStore, error) {
	d := filepath.Join(dir, "actions")
	if err := os.MkdirAll(d, 0o750); err != nil {
		return nil, err
	}
	s := &ActionStore{dir: d, actions: map[string]*ActionRequest{}}
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err != nil {
			continue
		}
		var a ActionRequest
		if json.Unmarshal(raw, &a) == nil && a.ID != "" {
			s.actions[a.ID] = &a
		}
	}
	return s, nil
}

// Create queues a pending action after validating the closed enumeration.
func (s *ActionStore) Create(host, action string, pid int, path, exe string, startTicks uint64, reason, by string) (*ActionRequest, error) {
	if !allowedActions[action] {
		return nil, fmt.Errorf("action %q is not in the allowed set (center cannot dispatch arbitrary commands)", action)
	}
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	now := time.Now().UTC()
	a := &ActionRequest{
		ID: fmt.Sprintf("act-%d", now.UnixNano()), Host: host, Action: action,
		PID: pid, Path: path, Exe: exe, StartTicks: startTicks, Reason: reason,
		State: "pending", RequestedBy: by, CreatedAt: now, UpdatedAt: now,
	}
	a.Timeline = append(a.Timeline, CaseEvent{At: now, Kind: "created", Detail: action + " on " + host})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions[a.ID] = a
	return a, s.saveLocked(a)
}

// List returns actions newest-first.
func (s *ActionStore) List() []*ActionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ActionRequest, 0, len(s.actions))
	for _, a := range s.actions {
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Get returns an action by id.
func (s *ActionStore) Get(id string) (*ActionRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.actions[id]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// Approve marks a pending action approved.
func (s *ActionStore) Approve(id, by string) error {
	return s.transition(id, "pending", "approved", func(a *ActionRequest) { a.ApprovedBy = by }, "approved by "+by)
}

// Reject marks a pending action rejected.
func (s *ActionStore) Reject(id, by, reason string) error {
	return s.transition(id, "pending", "rejected", func(a *ActionRequest) { a.ApprovedBy = by }, "rejected: "+reason)
}

// PendingFor returns approved actions for host and marks them dispatched.
func (s *ActionStore) PendingFor(host string) []*ActionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ActionRequest
	for _, a := range s.actions {
		if a.Host != host || a.State != "approved" {
			continue
		}
		a.State = "dispatched"
		a.UpdatedAt = time.Now().UTC()
		a.Timeline = append(a.Timeline, CaseEvent{At: a.UpdatedAt, Kind: "dispatched"})
		_ = s.saveLocked(a)
		cp := *a
		out = append(out, &cp)
	}
	return out
}

// Complete records an agent result.
func (s *ActionStore) Complete(id string, success, enforced bool, detail string) error {
	return s.transition(id, "dispatched", "", func(a *ActionRequest) {
		if success {
			a.State = "completed"
		} else {
			a.State = "failed"
		}
		a.Enforced = enforced
		a.Result = detail
	}, detail)
}

func (s *ActionStore) transition(id, from, to string, fn func(*ActionRequest), detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.actions[id]
	if !ok {
		return fmt.Errorf("action %q not found", id)
	}
	if from != "" && a.State != from {
		return fmt.Errorf("action %q is %s, expected %s", id, a.State, from)
	}
	if to != "" {
		a.State = to
	}
	if fn != nil {
		fn(a)
	}
	a.UpdatedAt = time.Now().UTC()
	a.Timeline = append(a.Timeline, CaseEvent{At: a.UpdatedAt, Kind: a.State, Detail: detail})
	return s.saveLocked(a)
}

func (s *ActionStore) saveLocked(a *ActionRequest) error {
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, a.ID+".json"), raw, 0o640)
}
