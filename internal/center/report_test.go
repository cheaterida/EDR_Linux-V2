package center

import (
	"strings"
	"testing"
	"time"

	"edr/internal/event"
)

func TestReportAndExport(t *testing.T) {
	now := time.Now()
	evs := []event.Event{
		{Host: "h1", Time: now, Kind: event.KindExec, Comm: "bash",
			Detail: map[string]any{"matched_rules": []string{"T1059-001-shell"}, "severity": "high"}},
		{Host: "h1", Time: now.Add(time.Second), Kind: event.KindConnect,
			Net:    &event.NetInfo{RemoteAddr: "10.0.0.9", RemotePort: 4444},
			Detail: map[string]any{"matched_rules": []string{"T1071-c2"}, "severity": "critical"}},
	}
	cef := ExportCEF(evs)
	if len(cef) != 2 || !strings.HasPrefix(cef[0], "CEF:0|EDR|") {
		t.Fatalf("cef = %v", cef)
	}
	leef := ExportLEEF(evs)
	if len(leef) != 2 || !strings.HasPrefix(leef[0], "LEEF:2.0|EDR|") {
		t.Fatalf("leef = %v", leef)
	}
	if !strings.Contains(cef[1], "dst=10.0.0.9") {
		t.Fatalf("cef missing dst: %s", cef[1])
	}
}

func TestBuildReport(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Ingest(event.Event{Host: "h1", Time: time.Now().UTC(), Kind: event.KindExec,
		Detail: map[string]any{"matched_rules": []string{"T1059-001-shell"}, "severity": "high"}})
	cs, _ := OpenCases(t.TempDir())
	rep := BuildReport(s, cs)
	if rep.TotalEvents != 1 || len(rep.Hosts) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.TacticCounts["execution"] != 1 {
		t.Fatalf("tactic counts = %+v", rep.TacticCounts)
	}
	if len(rep.TopRules) != 1 || rep.TopRules[0].RuleID != "T1059-001-shell" {
		t.Fatalf("top rules = %+v", rep.TopRules)
	}
	if md := RenderMarkdown(rep); !strings.Contains(md, "# EDR report") {
		t.Fatalf("markdown = %s", md)
	}
}
