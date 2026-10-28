package center

import (
	"fmt"
	"sort"
	"time"

	"edr/internal/event"
)

// Finding is a correlated observation over one or more hosts.
type Finding struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // host_chain | cross_host_indicator
	Hosts      []string  `json:"hosts"`
	Rules      []string  `json:"rules"`
	Tactics    []string  `json:"tactics"`
	Techniques []string  `json:"techniques"`
	Severity   string    `json:"severity"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int       `json:"count"`
	Summary    string    `json:"summary"`
}

// Correlate builds findings from events. window bounds how far apart events
// may be to belong to the same host chain (per host).
func Correlate(events []event.Event, window time.Duration) []Finding {
	if window <= 0 {
		window = 15 * time.Minute
	}
	evs := append([]event.Event(nil), events...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })

	// Group by host.
	byHost := map[string][]event.Event{}
	for _, ev := range evs {
		byHost[ev.Host] = append(byHost[ev.Host], ev)
	}

	var findings []Finding
	for host, list := range byHost {
		f := correlateHost(host, list, window)
		if f != nil {
			findings = append(findings, *f)
		}
	}
	findings = append(findings, correlateIndicators(evs)...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].LastSeen.Before(findings[j].LastSeen) })
	return findings
}

func correlateHost(host string, list []event.Event, window time.Duration) *Finding {
	if len(list) == 0 {
		return nil
	}
	// Take the most recent window worth of events.
	start := len(list) - 1
	for start > 0 && list[len(list)-1].Time.Sub(list[start-1].Time) <= window {
		start--
	}
	seg := list[start:]
	f := Finding{Kind: "host_chain", Hosts: []string{host}, Count: len(seg),
		FirstSeen: seg[0].Time, LastSeen: seg[len(seg)-1].Time}
	severity := ""
	ruleSet := map[string]bool{}
	tacSet := map[string]bool{}
	tecSet := map[string]bool{}
	for _, ev := range seg {
		for _, r := range ruleIDsOf(ev) {
			if !ruleSet[r] {
				ruleSet[r] = true
				f.Rules = append(f.Rules, r)
				a := Tag(r)
				if !tacSet[a.Tactic] {
					tacSet[a.Tactic] = true
					f.Tactics = append(f.Tactics, a.Tactic)
				}
				if !tecSet[a.Technique] {
					tecSet[a.Technique] = true
					f.Techniques = append(f.Techniques, a.Technique)
				}
			}
		}
		if sev := ev.Severity(); severityRank(sev) > severityRank(severity) {
			severity = sev
		}
	}
	if severity == "" {
		severity = "low"
	}
	f.Severity = severity
	sort.Strings(f.Rules)
	sort.Strings(f.Tactics)
	sort.Strings(f.Techniques)
	f.ID = fmt.Sprintf("chain-%s-%d", host, f.LastSeen.Unix())
	f.Summary = fmt.Sprintf("%d events on %s across %d rule(s)", f.Count, host, len(f.Rules))
	return &f
}

// correlateIndicators links hosts that observed the same remote address.
func correlateIndicators(evs []event.Event) []Finding {
	type agg struct {
		hosts     map[string]bool
		rules     map[string]bool
		firstSeen time.Time
		lastSeen  time.Time
	}
	byIndicator := map[string]*agg{}
	for _, ev := range evs {
		if ev.Net == nil || ev.Net.RemoteAddr == "" {
			continue
		}
		a := byIndicator[ev.Net.RemoteAddr]
		if a == nil {
			a = &agg{hosts: map[string]bool{}, rules: map[string]bool{}, firstSeen: ev.Time, lastSeen: ev.Time}
			byIndicator[ev.Net.RemoteAddr] = a
		}
		a.hosts[ev.Host] = true
		for _, r := range ruleIDsOf(ev) {
			a.rules[r] = true
		}
		if ev.Time.Before(a.firstSeen) {
			a.firstSeen = ev.Time
		}
		if ev.Time.After(a.lastSeen) {
			a.lastSeen = ev.Time
		}
	}
	var findings []Finding
	for ind, a := range byIndicator {
		if len(a.hosts) < 2 {
			continue // single-host indicator is already covered by host_chain
		}
		f := Finding{Kind: "cross_host_indicator", Count: len(a.hosts),
			FirstSeen: a.firstSeen, LastSeen: a.lastSeen, Severity: "high"}
		for h := range a.hosts {
			f.Hosts = append(f.Hosts, h)
		}
		for r := range a.rules {
			f.Rules = append(f.Rules, r)
			aa := Tag(r)
			f.Tactics = appendUnique(f.Tactics, aa.Tactic)
			f.Techniques = appendUnique(f.Techniques, aa.Technique)
		}
		sort.Strings(f.Hosts)
		sort.Strings(f.Rules)
		f.ID = "xhost-" + ind
		f.Summary = fmt.Sprintf("remote address %s observed on %d hosts", ind, len(a.hosts))
		findings = append(findings, f)
	}
	return findings
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func ruleIDsOf(ev event.Event) []string {
	var out []string
	if ev.Detail == nil {
		return out
	}
	add := func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []string:
			out = append(out, t...)
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	add(ev.Detail["response_rule"])
	add(ev.Detail["sequence_rules"])
	add(ev.Detail["matched_rules"])
	return out
}
