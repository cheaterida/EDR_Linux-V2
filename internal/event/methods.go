package event

// ruleIDs collects the rule identifiers stamped into Detail by the detect
// stage, across response / sequence / matched rule keys.
func (e *Event) ruleIDs() []string {
	if e.Detail == nil {
		return nil
	}
	var out []string
	appendStr := func(v any) {
		switch t := v.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
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
	appendStr(e.Detail["response_rule"])
	appendStr(e.Detail["sequence_rules"])
	appendStr(e.Detail["matched_rules"])
	return out
}

// HasRule reports whether the event was flagged by the named rule.
func (e *Event) HasRule(rule string) bool {
	for _, r := range e.ruleIDs() {
		if r == rule {
			return true
		}
	}
	return false
}

// ChainRule returns the primary rule id for the event (for summaries).
func (e *Event) ChainRule() string {
	if ids := e.ruleIDs(); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// Severity returns the severity stamped by the detect stage, or "".
func (e *Event) Severity() string {
	if e.Detail == nil {
		return ""
	}
	if s, ok := e.Detail["severity"].(string); ok {
		return s
	}
	return ""
}
