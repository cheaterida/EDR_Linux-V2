package center

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"edr/internal/event"
)

// Report is an aggregated operational summary.
type Report struct {
	GeneratedAt  time.Time      `json:"generated_at"`
	Hosts        []HostState    `json:"hosts"`
	TotalEvents  int            `json:"total_events"`
	TotalGaps    uint64         `json:"total_gaps"`
	TopRules     []RuleCount    `json:"top_rules"`
	TacticCounts map[string]int `json:"tactic_counts"`
	Cases        []*Case        `json:"cases,omitempty"`
}

// RuleCount is a rule hit tally.
type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// BuildReport aggregates the store (and optionally cases) into a report.
func BuildReport(store *Store, cases *CaseStore) Report {
	rep := Report{GeneratedAt: time.Now().UTC(), TacticCounts: map[string]int{}}
	rep.Hosts = store.Hosts()
	for _, h := range rep.Hosts {
		rep.TotalGaps += h.Gaps
	}
	events, _ := store.Query(Filter{Limit: 1_000_000})
	rep.TotalEvents = len(events)
	ruleCount := map[string]int{}
	for _, ev := range events {
		for _, r := range ruleIDsOf(ev) {
			ruleCount[r]++
			t := Tag(r).Tactic
			rep.TacticCounts[t]++
		}
	}
	for r, c := range ruleCount {
		rep.TopRules = append(rep.TopRules, RuleCount{RuleID: r, Count: c})
	}
	sort.Slice(rep.TopRules, func(i, j int) bool {
		if rep.TopRules[i].Count != rep.TopRules[j].Count {
			return rep.TopRules[i].Count > rep.TopRules[j].Count
		}
		return rep.TopRules[i].RuleID < rep.TopRules[j].RuleID
	})
	if len(rep.TopRules) > 20 {
		rep.TopRules = rep.TopRules[:20]
	}
	if cases != nil {
		rep.Cases = cases.List()
	}
	return rep
}

// RenderMarkdown renders a human-readable report.
func RenderMarkdown(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# EDR report\n\nGenerated: %s\n\n", rep.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Hosts: %d, events: %d, chain gaps: %d\n\n", len(rep.Hosts), rep.TotalEvents, rep.TotalGaps)
	b.WriteString("## Hosts\n\n| host | events | last_seq | gaps | last_seen |\n|---|---|---|---|---|\n")
	for _, h := range rep.Hosts {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", h.HostID, h.Events, h.LastSeq, h.Gaps, h.LastSeen.Format(time.RFC3339))
	}
	b.WriteString("\n## Top rules\n\n| rule | hits |\n|---|---|\n")
	for _, r := range rep.TopRules {
		fmt.Fprintf(&b, "| %s | %d |\n", r.RuleID, r.Count)
	}
	b.WriteString("\n## Tactics\n\n")
	tactics := make([]string, 0, len(rep.TacticCounts))
	for t := range rep.TacticCounts {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	for _, t := range tactics {
		fmt.Fprintf(&b, "- %s: %d\n", t, rep.TacticCounts[t])
	}
	if len(rep.Cases) > 0 {
		b.WriteString("\n## Cases\n\n| id | status | severity | disposition |\n|---|---|---|---|\n")
		for _, c := range rep.Cases {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.ID, c.Status, c.Severity, c.Disposition)
		}
	}
	return b.String()
}

func cefSeverity(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 2
	default:
		return 0
	}
}

func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ExportCEF renders events as ArcSight CEF lines.
func ExportCEF(events []event.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		rule := ev.ChainRule()
		if rule == "" {
			rule = "edr-event"
		}
		name := ev.Kind.String()
		sev := cefSeverity(ev.Severity())
		ext := fmt.Sprintf("dhost=%s rt=%d mrt=%d", cefEscape(ev.Host), ev.Time.UnixMilli(),
			ev.Time.UnixMilli())
		if ev.PID != 0 {
			ext += fmt.Sprintf(" spid=%d", ev.PID)
		}
		if ev.Comm != "" {
			ext += " suser= proc=" + cefEscape(ev.Comm)
		}
		if ev.Net != nil && ev.Net.RemoteAddr != "" {
			ext += fmt.Sprintf(" dst=%s dpt=%d", cefEscape(ev.Net.RemoteAddr), ev.Net.RemotePort)
		}
		if ev.File != nil && ev.File.Path != "" {
			ext += " fname=" + cefEscape(ev.File.Path)
		}
		out = append(out, fmt.Sprintf("CEF:0|EDR|edr-agent|2.0|%s|%s|%d|%s",
			cefEscape(rule), cefEscape(name), sev, ext))
	}
	return out
}

// ExportLEEF renders events as IBM QRadar LEEF lines.
func ExportLEEF(events []event.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		rule := ev.ChainRule()
		if rule == "" {
			rule = "edr-event"
		}
		fields := []string{
			"host=" + ev.Host,
			"sev=" + fmt.Sprintf("%d", cefSeverity(ev.Severity())),
			"kind=" + ev.Kind.String(),
			"pid=" + fmt.Sprintf("%d", ev.PID),
		}
		if ev.Comm != "" {
			fields = append(fields, "proc="+ev.Comm)
		}
		if ev.Net != nil && ev.Net.RemoteAddr != "" {
			fields = append(fields, "dst="+ev.Net.RemoteAddr)
		}
		if ev.File != nil && ev.File.Path != "" {
			fields = append(fields, "fname="+ev.File.Path)
		}
		out = append(out, fmt.Sprintf("LEEF:2.0|EDR|edr-agent|2.0|%s|\t%s", rule, strings.Join(fields, "\t")))
	}
	return out
}
