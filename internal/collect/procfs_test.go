package collect

import (
	"os"
	"testing"
	"time"

	"edr/internal/event"
)

func TestEnrichSelf(t *testing.T) {
	// /proc reads can transiently fail under load; retry a few times.
	var last *event.Event
	for attempt := 0; attempt < 5; attempt++ {
		ev := &event.Event{Kind: event.KindExec, PID: uint32(os.Getpid())}
		Enrich(ev, Fields{Cmdline: true, Namespaces: true, ParentName: true})
		last = ev
		if ev.Proc != nil && len(ev.Proc.Cmdline) > 0 && ev.Proc.StartTicks != 0 &&
			ev.Proc.Namespaces != nil && ev.Proc.Namespaces.PID != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("enrichment incomplete after retries: %+v", last.Proc)
}

func TestEnrichMissingPIDDoesNotPanic(t *testing.T) {
	ev := &event.Event{Kind: event.KindExec, PID: 999999}
	Enrich(ev, Fields{Cmdline: true, Environ: true, MapsLibs: true, Container: true})
	if ev.Proc == nil {
		t.Fatal("Proc should be initialized even if /proc is missing")
	}
	if len(ev.Proc.Cmdline) != 0 {
		t.Fatalf("unexpected cmdline for dead pid: %v", ev.Proc.Cmdline)
	}
}
