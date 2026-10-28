// Package policy defines the detection policy: the serializable rule model,
// its condition tree, validation, and the aggregated decision split.
//
// The condition tree is intentionally a plain, JSON-friendly recursive
// struct so it can be signed, diffed and compiled on both the Go and Rust
// sides without a schema generator.
package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the policy document version accepted by this engine.
const SchemaVersion = "v2.0"

// AcceptedSchemaVersions lists loadable schema versions.
var AcceptedSchemaVersions = []string{"v2.0"}

const maxPolicyBytes = 2 << 20 // 2 MiB

// Decision values.
const (
	DecisionAllow = "allow"
	DecisionAlert = "alert"
	DecisionBlock = "block"
)

// Action values.
const (
	ActionNone           = "none"
	ActionLog            = "log"
	ActionKill           = "kill"
	ActionKillTree       = "kill_tree"
	ActionQuarantine     = "quarantine"
	ActionFixPermission  = "fix_permissions"
	ActionNFTBlock       = "nft_block"
	ActionNetworkIsolate = "network_isolate"
	ActionProcessSuspend = "process_suspend"
	ActionFanotifyDeny   = "fanotify_deny"
)

// Effect values.
const (
	EffectAudit    = "audit"
	EffectResponse = "response"
)

// Categories.
const (
	CategoryProcess = "process"
	CategoryFile    = "file"
	CategoryNetwork = "network"
	CategoryRootkit = "rootkit"
)

// Field is the name of an addressable event attribute. It is an alias for
// string so the constants below stay plain strings while code can still write
// map[policy.Field]bool for the "needed fields" set.
type Field = string

// Fields addressable in a condition predicate.
const (
	FieldProcessName = "process_name"
	FieldProcessPath = "process_path"
	FieldCmdline     = "cmdline"
	FieldParentName  = "parent_name"
	FieldEnviron     = "environ"
	FieldMapsLibs    = "maps_libs"
	FieldFilePath    = "file_path"
	FieldFileOp      = "file_op"
	FieldRemoteAddr  = "remote_addr"
	FieldLocalPort   = "local_port"
	FieldProtocol    = "protocol"
	FieldUID         = "uid"
	FieldEUID        = "euid"
	FieldContainerID = "container_id"

	// probe-sourced detail fields
	FieldPrivType = "privtype"
	FieldBpfCmd   = "bpf_cmd"
	FieldModule   = "module"

	// event discriminator
	FieldEventKind   = "event_kind"
	FieldRootkitType = "rootkit_type"
)

// Op is a logical or comparison operator in a condition tree.
type Op string

const (
	OpAnd         Op = "and"
	OpOr          Op = "or"
	OpNot         Op = "not"
	OpEq          Op = "eq"
	OpNe          Op = "ne"
	OpContains    Op = "contains"
	OpNotContains Op = "not_contains"
	OpStartsWith  Op = "starts_with"
	OpEndsWith    Op = "ends_with"
	OpRegex       Op = "regex"
	OpGt          Op = "gt"
	OpLt          Op = "lt"
	OpGe          Op = "ge"
	OpLe          Op = "le"
	OpIn          Op = "in"
)

func (o Op) isLogical() bool { return o == OpAnd || o == OpOr || o == OpNot }
func (o Op) isCompare() bool {
	switch o {
	case OpEq, OpNe, OpContains, OpNotContains, OpStartsWith, OpEndsWith,
		OpRegex, OpGt, OpLt, OpGe, OpLe, OpIn:
		return true
	}
	return false
}

// Node is a recursive condition node.
type Node struct {
	Op    Op     `json:"op"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
	Args  []Node `json:"args,omitempty"`
}

// Rule is a single detection rule.
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Decision    string   `json:"decision"`
	Action      string   `json:"action"`
	Priority    int      `json:"priority,omitempty"`
	Effect      []string `json:"effect,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	When        *Node    `json:"when"`
	Allow       *Node    `json:"allow,omitempty"`
}

// IsEnabled defaults to true when the field is absent.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// EffectivePriority defaults to DefaultPriority.
func (r Rule) EffectivePriority() int {
	if r.Priority == 0 {
		return DefaultPriority
	}
	return r.Priority
}

// EffectiveEffect defaults to {audit, response}.
func (r Rule) EffectiveEffect() []string {
	if len(r.Effect) == 0 {
		return []string{EffectAudit, EffectResponse}
	}
	return r.Effect
}

// HasEffect reports whether the rule carries the named effect.
func (r Rule) HasEffect(name string) bool {
	for _, e := range r.EffectiveEffect() {
		if e == name {
			return true
		}
	}
	return false
}

// DefaultPriority applies to rules that omit priority.
const DefaultPriority = 100

// Rule priority bounds.
const (
	MinPriority = 0
	MaxPriority = 1000
)

// ProcessAccess is the process allow/deny configuration.
type ProcessAccess struct {
	Mode      string `json:"mode"`
	Whitelist []Node `json:"whitelist,omitempty"`
	Blacklist []Node `json:"blacklist,omitempty"`
	Action    string `json:"action"`
	Severity  string `json:"severity,omitempty"`
}

// SelfProtection configures agent self-defense.
type SelfProtection struct {
	Enabled     bool   `json:"enabled"`
	EnforceMode string `json:"enforce_mode,omitempty"` // "kill" or ""
}

// Policy is a complete detection policy document.
type Policy struct {
	SchemaVersion  string          `json:"schema_version"`
	ProcessAccess  *ProcessAccess  `json:"process_access,omitempty"`
	SelfProtection *SelfProtection `json:"self_protection,omitempty"`
	Rules          []Rule          `json:"rules"`
	Sequences      []SequenceRule  `json:"sequences,omitempty"`
}

// SequenceRule matches an ordered chain of stages within a time window.
type SequenceRule struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Decision    string   `json:"decision"`
	Action      string   `json:"action"`
	Priority    int      `json:"priority,omitempty"`
	Effect      []string `json:"effect,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	// Stages are matched in order; each stage is a normal condition node.
	Stages []Node `json:"stages"`
	// WithinSec is the maximum time between the first and last stage.
	WithinSec int `json:"within_sec"`
	// SamePID restricts the chain to a single process.
	SamePID bool `json:"same_pid,omitempty"`
}

// IsEnabled defaults to true.
func (r SequenceRule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// EffectivePriority defaults to DefaultPriority.
func (r SequenceRule) EffectivePriority() int {
	if r.Priority == 0 {
		return DefaultPriority
	}
	return r.Priority
}

// HasEffect reports whether the sequence carries the named effect.
func (r SequenceRule) HasEffect(name string) bool {
	fx := r.Effect
	if len(fx) == 0 {
		fx = []string{EffectAudit, EffectResponse}
	}
	for _, e := range fx {
		if e == name {
			return true
		}
	}
	return false
}

// LoadFile reads and validates a policy from path.
func LoadFile(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxPolicyBytes {
		return nil, fmt.Errorf("policy file size %d exceeds limit %d", fi.Size(), maxPolicyBytes)
	}
	return Load(io.LimitReader(f, maxPolicyBytes+1))
}

// Load decodes and validates a policy from r.
func Load(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the whole document.
func (p *Policy) Validate() error {
	if !acceptedVersion(p.SchemaVersion) {
		return fmt.Errorf("unsupported schema_version %q (accepted: %v)", p.SchemaVersion, AcceptedSchemaVersions)
	}
	if p.ProcessAccess != nil {
		if err := p.ProcessAccess.validate(); err != nil {
			return err
		}
	}
	if p.SelfProtection != nil && p.SelfProtection.EnforceMode != "" && p.SelfProtection.EnforceMode != "kill" {
		return fmt.Errorf("self_protection.enforce_mode must be \"kill\" or empty")
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("rules[%d].id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if err := r.validate(); err != nil {
			return err
		}
	}
	for i := range p.Sequences {
		s := &p.Sequences[i]
		if strings.TrimSpace(s.ID) == "" {
			return fmt.Errorf("sequences[%d].id is required", i)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate rule/sequence id %q", s.ID)
		}
		seen[s.ID] = true
		if err := s.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *SequenceRule) validate() error {
	if !oneOf(s.Category, CategoryProcess, CategoryFile, CategoryNetwork, CategoryRootkit) {
		return fmt.Errorf("sequence %s: invalid category %q", s.ID, s.Category)
	}
	if !oneOf(s.Decision, DecisionAllow, DecisionAlert, DecisionBlock) {
		return fmt.Errorf("sequence %s: invalid decision %q", s.ID, s.Decision)
	}
	if !oneOf(s.Action, ActionNone, ActionLog, ActionKill, ActionKillTree, ActionQuarantine,
		ActionFixPermission, ActionNFTBlock, ActionNetworkIsolate, ActionProcessSuspend, ActionFanotifyDeny) {
		return fmt.Errorf("sequence %s: invalid action %q", s.ID, s.Action)
	}
	if s.Decision == DecisionBlock && oneOf(s.Action, ActionNone, ActionLog) {
		return fmt.Errorf("sequence %s: decision=block requires a blocking action", s.ID)
	}
	if len(s.Stages) < 2 {
		return fmt.Errorf("sequence %s: requires at least 2 stages", s.ID)
	}
	if s.WithinSec <= 0 {
		return fmt.Errorf("sequence %s: within_sec must be > 0", s.ID)
	}
	for i := range s.Stages {
		if err := s.Stages[i].Validate(); err != nil {
			return fmt.Errorf("sequence %s stage[%d]: %w", s.ID, i, err)
		}
	}
	return nil
}

func (r *Rule) validate() error {
	if !oneOf(r.Category, CategoryProcess, CategoryFile, CategoryNetwork, CategoryRootkit) {
		return fmt.Errorf("rule %s: invalid category %q", r.ID, r.Category)
	}
	if !oneOf(r.Decision, DecisionAllow, DecisionAlert, DecisionBlock) {
		return fmt.Errorf("rule %s: invalid decision %q", r.ID, r.Decision)
	}
	if !oneOf(r.Action, ActionNone, ActionLog, ActionKill, ActionKillTree, ActionQuarantine,
		ActionFixPermission, ActionNFTBlock, ActionNetworkIsolate, ActionProcessSuspend, ActionFanotifyDeny) {
		return fmt.Errorf("rule %s: invalid action %q", r.ID, r.Action)
	}
	switch r.Decision {
	case DecisionAllow:
		if r.Action != ActionNone {
			return fmt.Errorf("rule %s: decision=allow requires action=none", r.ID)
		}
	case DecisionAlert:
		if !oneOf(r.Action, ActionNone, ActionLog) {
			return fmt.Errorf("rule %s: decision=alert requires action=none|log", r.ID)
		}
	case DecisionBlock:
		if !oneOf(r.Action, ActionKill, ActionKillTree, ActionQuarantine, ActionFixPermission,
			ActionNFTBlock, ActionNetworkIsolate, ActionProcessSuspend, ActionFanotifyDeny) {
			return fmt.Errorf("rule %s: decision=block requires a blocking action, got %q", r.ID, r.Action)
		}
	}
	if r.Priority < MinPriority || r.Priority > MaxPriority {
		return fmt.Errorf("rule %s: priority %d out of range", r.ID, r.Priority)
	}
	for _, e := range r.Effect {
		if !oneOf(e, EffectAudit, EffectResponse) {
			return fmt.Errorf("rule %s: invalid effect %q", r.ID, e)
		}
	}
	if r.When == nil {
		return fmt.Errorf("rule %s: when condition is required", r.ID)
	}
	if err := r.When.Validate(); err != nil {
		return fmt.Errorf("rule %s: when: %w", r.ID, err)
	}
	if r.Allow != nil {
		if err := r.Allow.Validate(); err != nil {
			return fmt.Errorf("rule %s: allow: %w", r.ID, err)
		}
	}
	return nil
}

func (pa *ProcessAccess) validate() error {
	if pa.Mode == "" && len(pa.Whitelist) == 0 && len(pa.Blacklist) == 0 {
		return nil
	}
	if !oneOf(pa.Mode, "monitor", "enforce") {
		return fmt.Errorf("process_access.mode must be monitor|enforce")
	}
	action := pa.Action
	if action == "" {
		action = ActionKill
	}
	if !oneOf(action, ActionNone, ActionKill, ActionKillTree) {
		return fmt.Errorf("process_access.action must be none|kill|kill_tree")
	}
	for i := range pa.Whitelist {
		if err := pa.Whitelist[i].Validate(); err != nil {
			return fmt.Errorf("process_access.whitelist[%d]: %w", i, err)
		}
	}
	for i := range pa.Blacklist {
		if err := pa.Blacklist[i].Validate(); err != nil {
			return fmt.Errorf("process_access.blacklist[%d]: %w", i, err)
		}
	}
	return nil
}

// Validate checks the node recursively.
func (n *Node) Validate() error {
	if n == nil {
		return fmt.Errorf("nil node")
	}
	if n.Op.isLogical() {
		switch n.Op {
		case OpNot:
			if len(n.Args) != 1 {
				return fmt.Errorf("not requires exactly 1 arg, got %d", len(n.Args))
			}
		default:
			if len(n.Args) < 1 {
				return fmt.Errorf("%s requires at least 1 arg", n.Op)
			}
		}
		if n.Field != "" || n.Value != "" {
			return fmt.Errorf("logical op %s must not carry field/value", n.Op)
		}
		for i := range n.Args {
			if err := n.Args[i].Validate(); err != nil {
				return err
			}
		}
		return nil
	}
	if !n.Op.isCompare() {
		return fmt.Errorf("unknown op %q", n.Op)
	}
	if n.Field == "" {
		return fmt.Errorf("comparison op %s requires a field", n.Op)
	}
	if len(n.Args) != 0 {
		return fmt.Errorf("comparison op %s must not carry args", n.Op)
	}
	return nil
}

// AggregatedDecision splits matches into a single response rule and the
// audit set. matches must already be ordered by ascending priority.
func AggregatedDecision(matches []Rule) (response *Rule, audit []Rule) {
	for i := range matches {
		r := matches[i]
		if r.HasEffect(EffectAudit) {
			audit = append(audit, r)
		}
		if response == nil && r.HasEffect(EffectResponse) &&
			r.Decision != DecisionAllow && r.Action != ActionNone {
			rc := r
			response = &rc
		}
	}
	return response, audit
}

// SortByPriority stable-sorts rules by ascending effective priority.
func SortByPriority(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].EffectivePriority() < rules[j].EffectivePriority()
	})
}

// Now is the clock indirection used by callers that need determinism.
var Now = time.Now

func acceptedVersion(v string) bool {
	for _, a := range AcceptedSchemaVersions {
		if v == a {
			return true
		}
	}
	return false
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
