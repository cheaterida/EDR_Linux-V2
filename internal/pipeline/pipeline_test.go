package pipeline

import (
	"errors"
	"sync"
	"testing"
	"time"

	"edr/internal/event"
)

// stageFunc adapts a function to the Stage interface.
type stageFunc struct {
	name string
	fn   func(*event.Event) (bool, error)
}

func (s stageFunc) Name() string { return s.name }
func (s stageFunc) Handle(ev *event.Event) (bool, error) {
	return s.fn(ev)
}

// recorder is a test stage that appends its name to a shared log.
type recorder struct {
	name string
	mu   *sync.Mutex
	log  *[]string
	keep bool
}

func (r recorder) Name() string { return r.name }
func (r recorder) Handle(*event.Event) (bool, error) {
	r.mu.Lock()
	*r.log = append(*r.log, r.name)
	r.mu.Unlock()
	return r.keep, nil
}

func TestStageOrder(t *testing.T) {
	var mu sync.Mutex
	var log []string
	done := make(chan struct{}, 1) // buffered: worker may finish first
	p := New("t", 8,
		recorder{"a", &mu, &log, true},
		recorder{"b", &mu, &log, true},
		stageFunc{"final", func(*event.Event) (bool, error) {
			done <- struct{}{}
			return true, nil
		}},
	)
	p.Start()
	defer p.Close()

	if !p.Submit(&event.Event{Kind: event.KindExec}) {
		t.Fatal("submit should succeed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(log) != 2 || log[0] != "a" || log[1] != "b" {
		t.Fatalf("stage order = %v", log)
	}
	if got := p.Stats().PerStage["a"].Out; got != 1 {
		t.Fatalf("stage a out = %d", got)
	}
}

func TestBackpressureCountsDrops(t *testing.T) {
	p := New("bp", 1, recorder{"only", &sync.Mutex{}, &[]string{}, true})
	// Worker not started: each lane's capacity is 1.
	if !p.Submit(&event.Event{}) {
		t.Fatal("first submit should succeed")
	}
	if p.Submit(&event.Event{}) {
		t.Fatal("second submit should be dropped")
	}
	if got := p.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}

	if !p.SubmitUrgent(&event.Event{}) {
		t.Fatal("first urgent submit should succeed")
	}
	if p.SubmitUrgent(&event.Event{}) {
		t.Fatal("second urgent submit should be dropped")
	}
	if got := p.Stats().UrgentDropped; got != 1 {
		t.Fatalf("urgent dropped = %d, want 1", got)
	}
}

func TestStageStopShortCircuits(t *testing.T) {
	first := make(chan struct{})
	secondRan := make(chan struct{}, 1)
	p := New("stop", 4,
		stageFunc{"first", func(*event.Event) (bool, error) {
			close(first)
			return false, nil
		}},
		stageFunc{"second", func(*event.Event) (bool, error) {
			secondRan <- struct{}{}
			return true, nil
		}},
	)
	p.Start()
	defer p.Close()
	p.Submit(&event.Event{})

	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("first stage never ran")
	}
	select {
	case <-secondRan:
		t.Fatal("second stage ran despite keep=false")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStageErrorIsCounted(t *testing.T) {
	ran := make(chan struct{})
	p := New("err", 4, stageFunc{"boom", func(*event.Event) (bool, error) {
		close(ran)
		return false, errors.New("x")
	}})
	p.Start()
	defer p.Close()
	p.Submit(&event.Event{})

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("stage never ran")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && p.Stats().Errored == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := p.Stats().Errored; got != 1 {
		t.Fatalf("errored = %d, want 1", got)
	}
}
