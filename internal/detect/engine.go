// Package detect compiles a policy into a kind-indexed rule set and
// evaluates events against it.
//
// The index maps an event Kind to the subset of rules that can possibly
// match, so evaluation is O(rules-for-kind) rather than O(all rules) —
// the fix for the v0.9 "scan every rule" cost.
package detect

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"edr/internal/event"
	"edr/internal/policy"
)

// Engine is an immutable, compiled view of a policy. Safe for concurrent use.
type Engine struct {
	pol     *policy.Policy
	byKind  map[event.Kind][]policy.Rule
	rules   int
	reCache sync.Map // pattern -> *regexp.Regexp
}

// New compiles p into an Engine. Rules are pre-sorted by priority within
// each kind bucket so Match can return them in order without re-sorting.
func New(p *policy.Policy) *Engine {
	e := &Engine{pol: p, byKind: map[event.Kind][]policy.Rule{}}
	if p == nil {
		return e
	}
	for _, r := range p.Rules {
		if !r.IsEnabled() {
			continue
		}
		for _, k := range kindsForCategory(r.Category) {
			e.byKind[k] = append(e.byKind[k], r)
		}
		e.rules++
	}
	for k := range e.byKind {
		policy.SortByPriority(e.byKind[k])
	}
	return e
}

// Kinds returns the event families that have at least one rule.
func (e *Engine) Kinds() []event.Kind {
	out := make([]event.Kind, 0, len(e.byKind))
	for k := range e.byKind {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// NeededFields returns the set of policy fields referenced by any enabled
// rule. Callers use it to enrich only what the rule set requires.
func (e *Engine) NeededFields() map[policy.Field]bool {
	out := map[policy.Field]bool{}
	if e == nil || e.pol == nil {
		return out
	}
	for i := range e.pol.Rules {
		r := e.pol.Rules[i]
		if !r.IsEnabled() {
			continue
		}
		collectFields(r.When, out)
		collectFields(r.Allow, out)
	}
	return out
}

func collectFields(n *policy.Node, out map[policy.Field]bool) {
	if n == nil {
		return
	}
	if n.Field != "" {
		out[policy.Field(n.Field)] = true
	}
	for i := range n.Args {
		collectFields(&n.Args[i], out)
	}
}

// RuleCount returns the number of rules that can match at least one kind.
func (e *Engine) RuleCount() int { return e.rules }

// Match returns every rule whose condition matches ev, ordered by ascending
// priority. Rule-level Allow overrides rewrite the decision to allow/none.
func (e *Engine) Match(ev *event.Event) []policy.Rule {
	if e == nil || ev == nil {
		return nil
	}
	candidates := e.byKind[ev.Kind]
	if len(candidates) == 0 {
		return nil
	}
	var out []policy.Rule
	for i := range candidates {
		r := candidates[i]
		if r.When == nil || !e.eval(r.When, ev) {
			continue
		}
		if r.Allow != nil && e.eval(r.Allow, ev) {
			r.Decision = policy.DecisionAllow
			r.Action = policy.ActionNone
		}
		out = append(out, r)
	}
	return out
}

// MatchAggregated is Match + AggregatedDecision in one call.
func (e *Engine) MatchAggregated(ev *event.Event) (*policy.Rule, []policy.Rule) {
	return policy.AggregatedDecision(e.Match(ev))
}

// EvalNode evaluates a condition node against ev (used by the sequence engine).
func (e *Engine) EvalNode(n *policy.Node, ev *event.Event) bool { return e.eval(n, ev) }

func (e *Engine) eval(n *policy.Node, ev *event.Event) bool {
	switch n.Op {
	case policy.OpAnd:
		for i := range n.Args {
			if !e.eval(&n.Args[i], ev) {
				return false
			}
		}
		return true
	case policy.OpOr:
		for i := range n.Args {
			if e.eval(&n.Args[i], ev) {
				return true
			}
		}
		return false
	case policy.OpNot:
		if len(n.Args) != 1 {
			return false
		}
		return !e.eval(&n.Args[0], ev)
	}
	actual, _ := fieldValue(ev, n.Field)
	return e.compare(n.Op, actual, n.Value)
}

func (e *Engine) compare(op policy.Op, actual, expected string) bool {
	switch op {
	case policy.OpEq:
		return actual == expected
	case policy.OpNe:
		return actual != expected
	case policy.OpContains:
		return strings.Contains(actual, expected)
	case policy.OpNotContains:
		return !strings.Contains(actual, expected)
	case policy.OpStartsWith:
		return strings.HasPrefix(actual, expected)
	case policy.OpEndsWith:
		return strings.HasSuffix(actual, expected)
	case policy.OpIn:
		for _, v := range strings.Split(expected, ",") {
			if strings.TrimSpace(v) == actual {
				return true
			}
		}
		return false
	case policy.OpRegex:
		re := e.regex(expected)
		return re != nil && re.MatchString(actual)
	case policy.OpGt, policy.OpLt, policy.OpGe, policy.OpLe:
		a, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
		b, err2 := strconv.ParseFloat(strings.TrimSpace(expected), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case policy.OpGt:
			return a > b
		case policy.OpLt:
			return a < b
		case policy.OpGe:
			return a >= b
		default:
			return a <= b
		}
	}
	return false
}

func (e *Engine) regex(pattern string) *regexp.Regexp {
	if v, ok := e.reCache.Load(pattern); ok {
		if re, _ := v.(*regexp.Regexp); re != nil {
			return re
		}
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		e.reCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil
	}
	e.reCache.Store(pattern, re)
	return re
}

// fieldValue resolves a policy field name against an event, returning the
// value and whether the field is present. A missing sub-structure yields "".
func fieldValue(ev *event.Event, field string) (string, bool) {
	switch field {
	case policy.FieldProcessName:
		return ev.Comm, ev.Comm != ""
	case policy.FieldProcessPath:
		if ev.Proc != nil {
			return ev.Proc.Exe, ev.Proc.Exe != ""
		}
	case policy.FieldCmdline:
		if ev.Proc != nil {
			return strings.Join(ev.Proc.Cmdline, " "), true
		}
	case policy.FieldEnviron:
		if ev.Proc != nil {
			return strings.Join(ev.Proc.Environ, "\n"), true
		}
	case policy.FieldMapsLibs:
		if ev.Proc != nil {
			return strings.Join(ev.Proc.MapsLibs, "\n"), true
		}
	case policy.FieldContainerID:
		if ev.Proc != nil {
			return ev.Proc.ContainerID, ev.Proc.ContainerID != ""
		}
	case policy.FieldParentName:
		return detailString(ev, "parent_name"), false
	case policy.FieldFilePath:
		if ev.File != nil {
			return ev.File.Path, ev.File.Path != ""
		}
	case policy.FieldFileOp:
		if ev.File != nil {
			return ev.File.Op, ev.File.Op != ""
		}
	case policy.FieldRemoteAddr:
		if ev.Net != nil {
			return ev.Net.RemoteAddr, ev.Net.RemoteAddr != ""
		}
	case policy.FieldLocalPort:
		if ev.Net != nil {
			return strconv.FormatUint(uint64(ev.Net.LocalPort), 10), true
		}
	case policy.FieldProtocol:
		if ev.Net != nil {
			return ev.Net.Protocol, ev.Net.Protocol != ""
		}
	case policy.FieldUID:
		return strconv.FormatUint(uint64(ev.UID), 10), true
	case policy.FieldEUID:
		return strconv.FormatUint(uint64(ev.EUID), 10), true
	case policy.FieldPrivType:
		return detailString(ev, "privtype"), false
	case policy.FieldModule:
		return detailString(ev, "module"), false
	case policy.FieldBpfCmd:
		return detailInt(ev, "bpf_cmd"), false
	case policy.FieldEventKind:
		return ev.Kind.String(), true
	case policy.FieldRootkitType:
		return detailString(ev, "rootkit_type"), false
	}
	return "", false
}

func detailInt(ev *event.Event, key string) string {
	if ev.Detail == nil {
		return ""
	}
	if v, ok := ev.Detail[key]; ok {
		switch n := v.(type) {
		case uint32:
			return strconv.FormatUint(uint64(n), 10)
		case int:
			return strconv.Itoa(n)
		case int64:
			return strconv.FormatInt(n, 10)
		case uint64:
			return strconv.FormatUint(n, 10)
		case float64:
			return strconv.FormatInt(int64(n), 10)
		case string:
			return n
		}
	}
	return ""
}

func detailString(ev *event.Event, key string) string {
	if ev.Detail == nil {
		return ""
	}
	if v, ok := ev.Detail[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// kindsForCategory maps a rule category to the event families it can match.
func kindsForCategory(category string) []event.Kind {
	switch category {
	case policy.CategoryProcess:
		return []event.Kind{
			event.KindExec, event.KindFork, event.KindExit, event.KindSelfProtect,
			event.KindPtrace, event.KindLDPreload, event.KindInstrument, event.KindPrivesc,
			event.KindMasquerade,
		}
	case policy.CategoryNetwork:
		return []event.Kind{event.KindConnect}
	case policy.CategoryFile:
		return []event.Kind{event.KindFileOp}
	case policy.CategoryRootkit:
		return []event.Kind{
			event.KindModuleLoad, event.KindModuleUnload, event.KindBPFOp, event.KindRootkit,
		}
	}
	return nil
}
