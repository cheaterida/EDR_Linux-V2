// Package rootkit implements cross-source consistency checks that expose common
// Ring-0 hiding techniques without assuming anything about process names:
//
//   - hidden processes:   a PID the probes saw alive but /proc does not list
//   - hidden modules:     a module in /sys/module but absent from /proc/modules
//   - hidden connections: a remote address seen by the probes but absent from
//     /proc/net/tcp
//   - syscall hooking:    a key syscall address outside the kernel .text segment
//
// Findings are emitted as KindRootkit events carrying a "rootkit_type"
// discriminator, so the normal policy engine decides severity and response.
// This keeps the detector free of hard-coded process/module name assumptions
// (the limitation of the legacy implementation).
package rootkit

import (
	"sync"
	"time"

	"edr/internal/event"
)

// Tracker accumulates what the agent's probes have observed. It is fed by the
// pipeline and read by the detector; all methods are safe for concurrent use.
//
// The address and process tables are pruned periodically: an address is only
// relevant for recent connections, and a process that never produced an exit
// event (ring-buffer drop) must not stay tracked forever. Without this the
// address map would grow without bound on a long-running host.
type Tracker struct {
	mu     sync.Mutex
	procs  map[int]sighting
	addrs  map[string]time.Time
	now    func() time.Time
	learns int
}

const (
	addrTTL    = 10 * time.Minute
	procTTL    = time.Hour
	pruneEvery = 1024
)

// sighting records when a PID was first and last observed, so a short-lived
// process that exited can be excluded before it is treated as "hidden".
type sighting struct {
	first time.Time
	last  time.Time
}

// NewTracker creates an empty tracker using the wall clock.
func NewTracker() *Tracker {
	return NewTrackerWithClock(time.Now)
}

// NewTrackerWithClock creates a tracker with an injectable clock (used by
// tests to backdate sightings).
func NewTrackerWithClock(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{
		procs: make(map[int]sighting),
		addrs: make(map[string]time.Time),
		now:   now,
	}
}

// Learn records an observed event. Intentionally cheap: exec/fork add a PID,
// exit removes it, connect records a remote address. Events emitted by the
// detector (KindRootkit) are ignored, so there is no feedback loop.
func (t *Tracker) Learn(ev *event.Event) {
	if ev == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	switch ev.Kind {
	case event.KindExec, event.KindFork:
		if ev.PID == 0 {
			return
		}
		s := t.procs[int(ev.PID)]
		if s.first.IsZero() {
			s.first = now
		}
		s.last = now
		t.procs[int(ev.PID)] = s
	case event.KindExit:
		delete(t.procs, int(ev.PID))
	case event.KindConnect:
		if ev.Net != nil && ev.Net.RemoteAddr != "" {
			t.addrs[ev.Net.RemoteAddr] = now
		}
	}
	t.learns++
	if t.learns%pruneEvery == 0 {
		t.pruneLocked(now)
	}
}

// pruneLocked drops stale sightings so the tables stay bounded on a host that
// runs for weeks. Caller must hold t.mu.
func (t *Tracker) pruneLocked(now time.Time) {
	for k, v := range t.addrs {
		if now.Sub(v) > addrTTL {
			delete(t.addrs, k)
		}
	}
	for k, v := range t.procs {
		if now.Sub(v.last) > procTTL {
			delete(t.procs, k)
		}
	}
}

// Len reports tracked PID and address counts (diagnostics).
func (t *Tracker) Len() (procs, addrs int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs), len(t.addrs)
}

func (t *Tracker) procSightings() map[int]sighting {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[int]sighting, len(t.procs))
	for k, v := range t.procs {
		out[k] = v
	}
	return out
}

func (t *Tracker) addrSightings() map[string]time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]time.Time, len(t.addrs))
	for k, v := range t.addrs {
		out[k] = v
	}
	return out
}
