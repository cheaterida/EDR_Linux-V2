// Package pipeline provides a bounded, staged event pipeline with explicit
// backpressure accounting and a separate high-priority lane for
// fail-closed enforcement events.
//
// Invariants:
//   - every channel is bounded; nothing blocks the producer
//   - drops are counted, never silent
//   - a stage error aborts only its own event, never the pipeline
package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"edr/internal/event"
)

// Stage processes a single event. Returning keep=false stops the event
// from reaching later stages. An error is recorded and also stops the
// event (the pipeline never panics on stage errors).
type Stage interface {
	Name() string
	Handle(ev *event.Event) (keep bool, err error)
}

type stageCounter struct {
	in      atomic.Uint64
	out     atomic.Uint64
	errored atomic.Uint64
	latNs   atomic.Uint64
}

// Stats is a point-in-time snapshot of pipeline counters.
type Stats struct {
	In            uint64
	Out           uint64
	Dropped       uint64 // normal lane drops
	UrgentDropped uint64 // urgent lane drops
	Errored       uint64
	PerStage      map[string]StageStats
}

type StageStats struct {
	In      uint64
	Out     uint64
	Errored uint64
	AvgNs   uint64
}

// Pipeline is safe for concurrent Submit from many producers.
type Pipeline struct {
	name    string
	stages  []Stage
	normal  chan *event.Event
	urgent  chan *event.Event
	stop    chan struct{}
	done    chan struct{}
	started atomic.Bool
	closed  atomic.Bool
	stopped sync.Once

	in         atomic.Uint64
	out        atomic.Uint64
	dropped    atomic.Uint64
	urgentDrop atomic.Uint64
	errored    atomic.Uint64

	counters []*stageCounter
}

// New builds a pipeline. capacity is the depth of both lanes.
func New(name string, capacity int, stages ...Stage) *Pipeline {
	if capacity <= 0 {
		capacity = 64
	}
	counters := make([]*stageCounter, len(stages))
	for i := range counters {
		counters[i] = &stageCounter{}
	}
	return &Pipeline{
		name:     name,
		stages:   stages,
		normal:   make(chan *event.Event, capacity),
		urgent:   make(chan *event.Event, capacity),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		counters: counters,
	}
}

// Start launches the worker goroutine. idempotent.
func (p *Pipeline) Start() {
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	go p.run()
}

// Submit enqueues a telemetry event on the normal lane. Returns false when
// the lane is full (the event is dropped and counted).
func (p *Pipeline) Submit(ev *event.Event) bool {
	if p.closed.Load() {
		return false
	}
	select {
	case p.normal <- ev:
		p.in.Add(1)
		return true
	default:
		p.dropped.Add(1)
		return false
	}
}

// SubmitUrgent enqueues a fail-closed event on the priority lane. The
// worker always drains urgent before normal.
func (p *Pipeline) SubmitUrgent(ev *event.Event) bool {
	if p.closed.Load() {
		return false
	}
	select {
	case p.urgent <- ev:
		p.in.Add(1)
		return true
	default:
		p.urgentDrop.Add(1)
		return false
	}
}

func (p *Pipeline) run() {
	defer close(p.done)
	for {
		// Prefer urgent.
		select {
		case ev := <-p.urgent:
			p.handle(ev)
			continue
		default:
		}
		select {
		case <-p.stop:
			return
		case ev := <-p.urgent:
			p.handle(ev)
		case ev := <-p.normal:
			p.handle(ev)
		}
	}
}

func (p *Pipeline) handle(ev *event.Event) {
	for i, st := range p.stages {
		c := p.counters[i]
		c.in.Add(1)
		start := time.Now()
		keep, err := st.Handle(ev)
		c.latNs.Add(uint64(time.Since(start).Nanoseconds()))
		if err != nil {
			c.errored.Add(1)
			p.errored.Add(1)
			return
		}
		if !keep {
			return
		}
		c.out.Add(1)
	}
	p.out.Add(1)
}

// Close stops the worker and waits for it to exit. Safe to call twice.
func (p *Pipeline) Close() {
	if !p.started.Load() {
		p.closed.Store(true)
		return
	}
	p.stopped.Do(func() {
		p.closed.Store(true)
		close(p.stop)
		<-p.done
	})
}

// Stats returns a snapshot of counters.
func (p *Pipeline) Stats() Stats {
	s := Stats{
		In:            p.in.Load(),
		Out:           p.out.Load(),
		Dropped:       p.dropped.Load(),
		UrgentDropped: p.urgentDrop.Load(),
		Errored:       p.errored.Load(),
		PerStage:      make(map[string]StageStats, len(p.stages)),
	}
	for i, st := range p.stages {
		c := p.counters[i]
		in := c.in.Load()
		var avg uint64
		if in > 0 {
			avg = c.latNs.Load() / in
		}
		s.PerStage[st.Name()] = StageStats{
			In:      in,
			Out:     c.out.Load(),
			Errored: c.errored.Load(),
			AvgNs:   avg,
		}
	}
	return s
}

// Name returns the pipeline name.
func (p *Pipeline) Name() string { return p.name }

// WaitContext blocks until ctx is done or the pipeline closes.
func (p *Pipeline) WaitContext(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-p.done:
	}
}
