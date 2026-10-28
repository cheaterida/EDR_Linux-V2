package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"edr/internal/event"
)

func evAt(sev string) *event.Event {
	return &event.Event{
		Host: "h1", Kind: event.KindExec, PID: 42, Comm: "bash",
		Detail: map[string]any{"severity": sev, "matched_rules": []string{"T1059-x"}},
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestWebhookDispatchAndSeverityFilter(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := New(Config{Webhooks: []WebhookConfig{{URL: srv.URL, Format: "generic", MinSeverity: "high"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.Notify(evAt("low"))  // filtered out
	d.Notify(evAt("high")) // delivered
	waitFor(t, func() bool { return hits.Load() == 1 })

	time.Sleep(50 * time.Millisecond)
	if hits.Load() != 1 {
		t.Fatalf("expected exactly 1 delivery, got %d", hits.Load())
	}
}

func TestDispatcherDropCounting(t *testing.T) {
	// No consumer started: the bounded queue must drop and count.
	d := New(Config{QueueSize: 1, Webhooks: []WebhookConfig{{URL: "http://127.0.0.1:0"}}})
	d.Notify(evAt("high"))
	d.Notify(evAt("high"))
	if d.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", d.Dropped())
	}
}

func TestDisabledWithoutChannels(t *testing.T) {
	d := New(Config{})
	if d.Enabled() {
		t.Fatal("empty config should be disabled")
	}
	// Notify on a disabled dispatcher must be a no-op.
	d.Notify(evAt("critical"))
	if d.Dropped() != 0 {
		t.Fatal("disabled dispatcher should not drop-count")
	}
}
