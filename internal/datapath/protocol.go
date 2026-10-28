// Package datapath is the Go client for the edr-datapath Rust daemon.
//
// It compiles the file-access slice of a policy into a compact decision table,
// pushes it to the daemon, and consumes file-access decisions as events.
//
// Wire format (see datapath/src/ipc.rs): [u32 LE body_len][u8 version][json].
package datapath

// FrameVersion must match FRAME_VERSION in datapath/src/ipc.rs.
const FrameVersion = 1

// FileRule is a single file-access decision entry in the pushed table.
type FileRule struct {
	ID         string `json:"id"`
	PathExact  string `json:"path_exact,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	PathSuffix string `json:"path_suffix,omitempty"`
	Decision   string `json:"decision"`
}

// Message is the union frame. A single struct (with omitempty) keeps the Go
// and Rust codecs trivially in sync; the "type" field discriminates.
type Message struct {
	Type string `json:"type"`

	// hello
	AgentPID uint32 `json:"agent_pid,omitempty"`

	// policy
	Version uint64     `json:"version,omitempty"`
	Rules   []FileRule `json:"rules,omitempty"`

	// event (daemon -> agent)
	Kind     uint16 `json:"kind,omitempty"`
	PID      int32  `json:"pid,omitempty"`
	Comm     string `json:"comm,omitempty"`
	Path     string `json:"path,omitempty"`
	Op       string `json:"op,omitempty"`
	Decision string `json:"decision,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`

	// action (agent -> daemon) / action_result (daemon -> agent)
	ID         string `json:"id,omitempty"`
	Action     string `json:"action,omitempty"`
	Exe        string `json:"exe,omitempty"`
	StartTicks uint64 `json:"start_ticks,omitempty"`
	Success    bool   `json:"success,omitempty"`
	Enforced   bool   `json:"enforced,omitempty"`
	Detail     string `json:"detail,omitempty"`

	// heartbeat
	TSms uint64 `json:"ts_ms,omitempty"`
}
