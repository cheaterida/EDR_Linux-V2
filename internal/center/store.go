// Package center implements the audit operations center: an authenticated
// ingest endpoint, an append-only per-host event store, per-host chain
// continuity checking, and an aggregated query API.
package center

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"edr/internal/event"
)

// HostState is the per-host continuity bookkeeping.
type HostState struct {
	HostID    string    `json:"host_id"`
	ChainID   string    `json:"chain_id,omitempty"`
	LastSeq   uint64    `json:"last_seq"`
	LastHash  string    `json:"last_hash,omitempty"`
	Events    uint64    `json:"events"`
	Gaps      uint64    `json:"gaps"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is an append-only, per-host event store with chain continuity checks.
type Store struct {
	mu   sync.Mutex
	dir  string
	host map[string]*HostState
}

// Open loads (or creates) a store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o750); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, host: map[string]*HostState{}}
	entries, _ := os.ReadDir(filepath.Join(dir, "hosts"))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := s.loadState(e.Name())
		if err == nil {
			s.host[e.Name()] = st
		}
	}
	return s, nil
}

func safeHost(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "unknown-host"
	}
	return strings.NewReplacer("/", "_", "..", "_", "\n", "_").Replace(id)
}

func (s *Store) hostDir(id string) string {
	return filepath.Join(s.dir, "hosts", safeHost(id))
}

func (s *Store) loadState(id string) (*HostState, error) {
	raw, err := os.ReadFile(filepath.Join(s.hostDir(id), "state.json"))
	if err != nil {
		return nil, err
	}
	var st HostState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if st.HostID == "" {
		st.HostID = id
	}
	return &st, nil
}

func (s *Store) saveState(st *HostState) {
	dir := s.hostDir(st.HostID)
	_ = os.MkdirAll(dir, 0o750)
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// Ingest stores an event, deduplicating by (host, chain_id, seq) and tracking
// chain continuity. Returns true if the event was newly stored.
func (s *Store) Ingest(ev event.Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	host := ev.Host
	st := s.host[host]
	if st == nil {
		st = &HostState{HostID: host, FirstSeen: time.Now().UTC()}
		s.host[host] = st
	}
	if ev.Chain != nil {
		if ev.Chain.ChainID != st.ChainID {
			st.ChainID = ev.Chain.ChainID
		}
		if ev.Chain.Seq <= st.LastSeq {
			return false // duplicate / out of order
		}
		if st.LastSeq != 0 {
			if ev.Chain.Seq != st.LastSeq+1 || (st.LastHash != "" && ev.Chain.PrevHash != st.LastHash) {
				st.Gaps++
			}
		}
		st.LastSeq = ev.Chain.Seq
		st.LastHash = ev.Chain.Hash
	}
	st.Events++
	st.LastSeen = time.Now().UTC()

	dir := s.hostDir(host)
	_ = os.MkdirAll(dir, 0o750)
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return false
	}
	line, err := json.Marshal(ev)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
	}
	_ = f.Close()
	s.saveState(st)
	return true
}

// IngestBatch stores many events, returning how many were new.
func (s *Store) IngestBatch(events []event.Event) int {
	n := 0
	for _, ev := range events {
		if s.Ingest(ev) {
			n++
		}
	}
	return n
}

// Filter selects events for a query.
type Filter struct {
	Host        string
	RuleID      string
	MinSeverity string
	Limit       int
}

// Query returns events matching f, newest last, capped at f.Limit.
func (s *Store) Query(f Filter) ([]event.Event, error) {
	s.mu.Lock()
	hosts := make([]string, 0, len(s.host))
	for h := range s.host {
		hosts = append(hosts, h)
	}
	s.mu.Unlock()
	if f.Host != "" {
		hosts = []string{f.Host}
	}
	sort.Strings(hosts)
	if f.Limit <= 0 {
		f.Limit = 100
	}
	minRank := severityRank(f.MinSeverity)
	var out []event.Event
	for _, h := range hosts {
		evs, err := readHostEvents(s.hostDir(h))
		if err != nil {
			continue
		}
		for _, ev := range evs {
			if f.RuleID != "" && !ev.HasRule(f.RuleID) {
				continue
			}
			if minRank > 0 && severityRank(ev.Severity()) < minRank {
				continue
			}
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	if len(out) > f.Limit {
		out = out[len(out)-f.Limit:]
	}
	return out, nil
}

func readHostEvents(dir string) ([]event.Event, error) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	var out []event.Event
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

// Hosts returns the current per-host state.
func (s *Store) Hosts() []HostState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HostState, 0, len(s.host))
	for _, st := range s.host {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
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
	default:
		return 0
	}
}

var _ = fmt.Sprintf
