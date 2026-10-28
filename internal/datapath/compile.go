package datapath

import (
	"edr/internal/policy"
)

// CompileFileRules extracts the file-access block rules from a policy and
// compiles them into the daemon's decision table.
//
// M1 supports the path predicates that matter for fanotify and leave the
// rest to the in-agent detector: exact / prefix / suffix on file_path inside
// an AND tree. Rules that cannot be expressed here are simply omitted (the
// agent still evaluates them).
func CompileFileRules(p *policy.Policy) []FileRule {
	var out []FileRule
	if p == nil {
		return out
	}
	for i := range p.Rules {
		r := p.Rules[i]
		if !r.IsEnabled() || r.Decision != policy.DecisionBlock || r.Category != policy.CategoryFile {
			continue
		}
		fr := FileRule{ID: r.ID, Decision: "block"}
		extractPath(r.When, &fr)
		if fr.PathExact == "" && fr.PathPrefix == "" && fr.PathSuffix == "" {
			continue
		}
		out = append(out, fr)
	}
	return out
}

func extractPath(n *policy.Node, fr *FileRule) {
	if n == nil {
		return
	}
	if n.Field == policy.FieldFilePath || n.Field == "file_path_prefix" {
		switch n.Op {
		case policy.OpEq:
			if fr.PathExact == "" {
				fr.PathExact = n.Value
			}
		case policy.OpStartsWith, "prefix":
			if fr.PathPrefix == "" {
				fr.PathPrefix = n.Value
			}
		case policy.OpEndsWith:
			if fr.PathSuffix == "" {
				fr.PathSuffix = n.Value
			}
		}
	}
	for i := range n.Args {
		extractPath(&n.Args[i], fr)
	}
}
