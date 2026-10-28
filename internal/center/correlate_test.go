package center

import (
	"testing"
	"time"

	"edr/internal/event"
)

func mkEvent(host string, t time.Time, rules []string, remote string) event.Event {
	ev := event.Event{Host: host, Time: t, Kind: event.KindExec}
	d := map[string]any{"matched_rules": rules, "severity": "high"}
	ev.Detail = d
	if remote != "" {
		ev.Net = &event.NetInfo{RemoteAddr: remote}
	}
	return ev
}

func TestTag(t *testing.T) {
	if a := Tag("T1059-001-shell"); a.Tactic != "execution" {
		t.Fatalf("tag = %+v", a)
	}
	if a := Tag("ATT002-ld-preload-injection"); a.Tactic != "privilege-escalation" {
		t.Fatalf("tag = %+v", a)
	}
	if a := Tag("whatever"); a.Tactic != "unknown" {
		t.Fatalf("unknown tag = %+v", a)
	}
}

func TestCorrelateHostChain(t *testing.T) {
	now := time.Now()
	evs := []event.Event{
		mkEvent("h1", now, []string{"T1059-001-shell"}, ""),
		mkEvent("h1", now.Add(time.Second), []string{"T1105-001-ingress"}, ""),
	}
	findings := Correlate(evs, time.Minute)
	var chain *Finding
	for i := range findings {
		if findings[i].Kind == "host_chain" {
			chain = &findings[i]
		}
	}
	if chain == nil {
		t.Fatal("no host_chain finding")
	}
	if len(chain.Techniques) != 2 {
		t.Fatalf("techniques = %v", chain.Techniques)
	}
}

func TestCorrelateCrossHostIndicator(t *testing.T) {
	now := time.Now()
	evs := []event.Event{
		mkEvent("h1", now, []string{"T1071-c2"}, "10.0.0.9"),
		mkEvent("h2", now.Add(time.Second), []string{"T1071-c2"}, "10.0.0.9"),
	}
	findings := Correlate(evs, time.Minute)
	found := false
	for _, f := range findings {
		if f.Kind == "cross_host_indicator" && len(f.Hosts) == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("cross-host indicator not correlated: %+v", findings)
	}
}
