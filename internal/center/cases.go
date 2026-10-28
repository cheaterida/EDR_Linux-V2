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

// Case lifecycle states.
var caseStatuses = map[string]bool{
	"new": true, "triage": true, "investigating": true, "contained": true, "closed": true,
}

var caseDispositions = map[string]bool{
	"": true, "true_positive": true, "false_positive": true, "benign": true,
}

// Note is an analyst annotation.
type Note struct {
	At     time.Time `json:"at"`
	Author string    `json:"author,omitempty"`
	Text   string    `json:"text"`
}

// CaseEvent is one timeline entry.
type CaseEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// Case is an investigation unit.
type Case struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Status      string      `json:"status"`
	Severity    string      `json:"severity"`
	Hosts       []string    `json:"hosts"`
	Rules       []string    `json:"rules"`
	Techniques  []string    `json:"techniques"`
	Disposition string      `json:"disposition,omitempty"`
	Notes       []Note      `json:"notes,omitempty"`
	Timeline    []CaseEvent `json:"timeline"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// CaseStore persists cases as one JSON file each.
type CaseStore struct {
	mu    sync.Mutex
	dir   string
	cases map[string]*Case
}

// OpenCases loads (or creates) the case store at dir/cases.
func OpenCases(dir string) (*CaseStore, error) {
	casesDir := filepath.Join(dir, "cases")
	if err := os.MkdirAll(casesDir, 0o750); err != nil {
		return nil, err
	}
	s := &CaseStore{dir: casesDir, cases: map[string]*Case{}}
	entries, _ := os.ReadDir(casesDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(casesDir, e.Name()))
		if err != nil {
			continue
		}
		var c Case
		if json.Unmarshal(raw, &c) == nil && c.ID != "" {
			s.cases[c.ID] = &c
		}
	}
	return s, nil
}

// Create opens a new case.
func (s *CaseStore) Create(title, severity string, hosts, rules, techniques []string) (*Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	c := &Case{
		ID:         fmt.Sprintf("case-%d", now.UnixNano()),
		Title:      title,
		Status:     "new",
		Severity:   severity,
		Hosts:      hosts,
		Rules:      rules,
		Techniques: techniques,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	c.Timeline = append(c.Timeline, CaseEvent{At: now, Kind: "created", Detail: title})
	s.cases[c.ID] = c
	if err := s.saveLocked(c); err != nil {
		return nil, err
	}
	return c, nil
}

// FromFinding opens a case from a correlation finding.
func (s *CaseStore) FromFinding(f Finding) (*Case, error) {
	return s.Create(f.Summary, f.Severity, f.Hosts, f.Rules, f.Techniques)
}

// List returns cases newest-first.
func (s *CaseStore) List() []*Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Case, 0, len(s.cases))
	for _, c := range s.cases {
		cp := *c
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Get returns a case by id.
func (s *CaseStore) Get(id string) (*Case, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// SetStatus advances the case state machine.
func (s *CaseStore) SetStatus(id, status string) error {
	if !caseStatuses[status] {
		return fmt.Errorf("invalid case status %q", status)
	}
	return s.mutate(id, func(c *Case) {
		c.Status = status
		c.Timeline = append(c.Timeline, CaseEvent{At: time.Now().UTC(), Kind: "status", Detail: status})
	})
}

// SetDisposition records the analyst verdict.
func (s *CaseStore) SetDisposition(id, disposition, note string) error {
	if !caseDispositions[disposition] {
		return fmt.Errorf("invalid disposition %q", disposition)
	}
	return s.mutate(id, func(c *Case) {
		c.Disposition = disposition
		if note != "" {
			c.Notes = append(c.Notes, Note{At: time.Now().UTC(), Text: note})
		}
		c.Timeline = append(c.Timeline, CaseEvent{At: time.Now().UTC(), Kind: "disposition", Detail: disposition})
	})
}

// AddNote appends an annotation.
func (s *CaseStore) AddNote(id, author, text string) error {
	return s.mutate(id, func(c *Case) {
		c.Notes = append(c.Notes, Note{At: time.Now().UTC(), Author: author, Text: text})
		c.Timeline = append(c.Timeline, CaseEvent{At: time.Now().UTC(), Kind: "note", Detail: text})
	})
}

func (s *CaseStore) mutate(id string, fn func(*Case)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return fmt.Errorf("case %q not found", id)
	}
	fn(c)
	c.UpdatedAt = time.Now().UTC()
	return s.saveLocked(c)
}

func (s *CaseStore) saveLocked(c *Case) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, c.ID+".json"), raw, 0o640)
}
