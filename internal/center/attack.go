package center

import "strings"

// Attack is a MITRE ATT&CK tactic/technique pair.
type Attack struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
}

// attackRules maps a rule-id prefix (or keyword) to an ATT&CK technique.
var attackRules = []struct {
	key string
	a   Attack
}{
	{"T1059", Attack{"execution", "T1059 Command and Scripting Interpreter"}},
	{"T1105", Attack{"command-and-control", "T1105 Ingress Tool Transfer"}},
	{"T1036", Attack{"defense-evasion", "T1036 Masquerading"}},
	{"T1547", Attack{"persistence", "T1547 Boot or Logon Autostart Execution"}},
	{"T1548", Attack{"privilege-escalation", "T1548 Abuse Elevation Control Mechanism"}},
	{"T1055", Attack{"defense-evasion", "T1055 Process Injection"}},
	{"T1014", Attack{"defense-evasion", "T1014 Rootkit"}},
	{"T1071", Attack{"command-and-control", "T1071 Application Layer Protocol"}},
	{"T1003", Attack{"credential-access", "T1003 OS Credential Dumping"}},
	{"T1070", Attack{"defense-evasion", "T1070 Indicator Removal"}},
	// keyword heuristics for human-named rules
	{"reverse-shell", Attack{"execution", "T1059 Command and Scripting Interpreter"}},
	{"ld-preload", Attack{"privilege-escalation", "T1574 Hijack Execution Flow"}},
	{"ptrace", Attack{"defense-evasion", "T1055 Process Injection"}},
	{"credential", Attack{"credential-access", "T1003 OS Credential Dumping"}},
	{"persist", Attack{"persistence", "T1547 Boot or Logon Autostart Execution"}},
	{"lateral", Attack{"lateral-movement", "T1021 Remote Services"}},
	{"privesc", Attack{"privilege-escalation", "T1068 Exploitation for Privilege Escalation"}},
	{"rootkit", Attack{"defense-evasion", "T1014 Rootkit"}},
	{"bpf", Attack{"defense-evasion", "T1014 Rootkit"}},
	{"module", Attack{"persistence", "T1547 Boot or Logon Autostart Execution"}},
	{"masquerade", Attack{"defense-evasion", "T1036 Masquerading"}},
	{"kworker", Attack{"defense-evasion", "T1036 Masquerading"}},
}

// Tag returns the ATT&CK mapping for a rule id, or a generic unknown entry.
func Tag(ruleID string) Attack {
	low := strings.ToLower(ruleID)
	for _, r := range attackRules {
		if strings.Contains(low, strings.ToLower(r.key)) {
			return r.a
		}
	}
	return Attack{Tactic: "unknown", Technique: "unmapped"}
}
