package detect

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"edr/internal/event"
	"edr/internal/policy"
)

// SequenceEngine tracks partial matches of ordered stage chains. It is the
// stateful complement to the stateless rule engine.
type SequenceEngine struct {
	mu         sync.Mutex
	state      map[seqKey]seqProgress
	maxEntries int
}

type seqKey struct {
	id  string
	key string
}

type seqProgress struct {
	stage int
	start time.Time
}

// NewSequenceEngine returns an empty tracker.
func NewSequenceEngine() *SequenceEngine {
	return &SequenceEngine{state: map[seqKey]seqProgress{}, maxEntries: 8192}
}

// Observe advances every sequence against ev and returns those that completed.
// Evaluation of stage conditions is delegated to eng (the current rule engine).
func (s *SequenceEngine) Observe(eng *Engine, p *policy.Policy, ev *event.Event) []policy.SequenceRule {
	if p == nil || eng == nil || len(p.Sequences) == 0 {
		return nil
	}
	now := time.Now()
	var fired []policy.SequenceRule

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range p.Sequences {
		sq := p.Sequences[i]
		if !sq.IsEnabled() {
			continue
		}
		key := ""
		if sq.SamePID {
			key = strconv.FormatUint(uint64(ev.PID), 10)
		}
		k := seqKey{sq.ID, key}
		st := s.state[k]
		window := time.Duration(sq.WithinSec) * time.Second
		if st.stage > 0 && now.Sub(st.start) > window {
			st = seqProgress{}
		}
		prog := st.stage
		if prog < len(sq.Stages) && eng.EvalNode(&sq.Stages[prog], ev) {
			if prog == 0 {
				st.start = now
			}
			prog++
			if prog >= len(sq.Stages) {
				fired = append(fired, sq)
				delete(s.state, k)
				continue
			}
			s.state[k] = seqProgress{stage: prog, start: st.start}
			continue
		}
		// No advance: allow a fresh chain to start on the first stage.
		if prog > 0 && eng.EvalNode(&sq.Stages[0], ev) {
			s.state[k] = seqProgress{stage: 1, start: now}
		}
	}
	s.evictLocked()
	return fired
}

// evictLocked bounds the map when many unique keys (PIDs) accumulate.
func (s *SequenceEngine) evictLocked() {
	if len(s.state) <= s.maxEntries {
		return
	}
	for k := range s.state {
		delete(s.state, k)
		if len(s.state) <= s.maxEntries {
			return
		}
	}
}

// Holder owns the current engine and sequence tracker and supports atomic
// hot-reload (swap the engine without stopping the pipeline).
type Holder struct {
	eng atomic.Pointer[Engine]
	pol atomic.Pointer[policy.Policy]
	seq *SequenceEngine
	mu  sync.Mutex
}

// NewHolder compiles p and returns a holder.
func NewHolder(p *policy.Policy) *Holder {
	h := &Holder{seq: NewSequenceEngine()}
	h.pol.Store(p)
	h.eng.Store(New(p))
	return h
}

// Engine returns the current compiled engine.
func (h *Holder) Engine() *Engine { return h.eng.Load() }

// Policy returns the current policy document.
func (h *Holder) Policy() *policy.Policy { return h.pol.Load() }

// Reload atomically swaps in a new policy.
func (h *Holder) Reload(p *policy.Policy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pol.Store(p)
	h.eng.Store(New(p))
}

// Match runs the stateless rules.
func (h *Holder) Match(ev *event.Event) []policy.Rule { return h.Engine().Match(ev) }

// Observe runs the stateful sequences.
func (h *Holder) Observe(ev *event.Event) []policy.SequenceRule {
	return h.seq.Observe(h.Engine(), h.Policy(), ev)
}

// NeededFields returns the policy fields referenced by the current rules.
func (h *Holder) NeededFields() map[policy.Field]bool { return h.Engine().NeededFields() }

// RuleCount returns the compiled rule count.
func (h *Holder) RuleCount() int { return h.Engine().RuleCount() }
