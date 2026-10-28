// Package event defines the single source of truth for the EDR event
// model and its schema version.
//
// Design goals (v2):
//   - typed sub-structures instead of an everything-map
//   - provenance/namespace captured from the start (avoids v0.9 S22 gap)
//   - enrichment is explicit and optional (nil == not collected)
//   - the on-wire/in-file schema is versioned so C/Go/Rust sides cannot drift
package event

import "time"

// SchemaVersion is stamped on every event. Bump on any breaking layout
// change. The C probes, Go pipeline and Rust datapath must agree.
const SchemaVersion = "v2.0"

// Kind enumerates event families. Values are part of the binary contract
// with the kernel probes; never renumber existing entries.
type Kind uint16

const (
	KindUnknown      Kind = 0
	KindExec         Kind = 1
	KindConnect      Kind = 2
	KindFork         Kind = 3
	KindExit         Kind = 4
	KindSelfProtect  Kind = 5
	KindPtrace       Kind = 6
	KindLDPreload    Kind = 7
	KindInstrument   Kind = 8
	KindPrivesc      Kind = 9
	KindModuleLoad   Kind = 10
	KindModuleUnload Kind = 11
	KindBPFOp        Kind = 12
	KindFileOp       Kind = 13
	KindMasquerade   Kind = 14
	KindRootkit      Kind = 15
)

var kindNames = map[Kind]string{
	KindUnknown:      "unknown",
	KindExec:         "exec",
	KindConnect:      "connect",
	KindFork:         "fork",
	KindExit:         "exit",
	KindSelfProtect:  "self_protect",
	KindPtrace:       "ptrace",
	KindLDPreload:    "ld_preload",
	KindInstrument:   "instrument",
	KindPrivesc:      "privesc",
	KindModuleLoad:   "module_load",
	KindModuleUnload: "module_unload",
	KindBPFOp:        "bpf_op",
	KindFileOp:       "file_op",
	KindMasquerade:   "masquerade",
	KindRootkit:      "rootkit",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "kind(" + itoa(uint64(k)) + ")"
}

// Valid reports whether k is a known event family.
func (k Kind) Valid() bool {
	_, ok := kindNames[k]
	return ok && k != KindUnknown
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// ChainMeta carries the audit hash-chain fields for an event. It is nil
// until the event is sealed by the audit chain.
type ChainMeta struct {
	Version  string `json:"integrity_version"`
	ChainID  string `json:"chain_id"`
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	HMAC     string `json:"hmac,omitempty"`
}

// NamespaceIDs records the inode identifiers of the process namespaces so
// cross-namespace PID confusion is detectable.
type NamespaceIDs struct {
	PID   uint64 `json:"pid,omitempty"`
	Mount uint64 `json:"mount,omitempty"`
	Net   uint64 `json:"net,omitempty"`
	User  uint64 `json:"user,omitempty"`
	UTS   uint64 `json:"uts,omitempty"`
	IPC   uint64 `json:"ipc,omitempty"`
}

// ProcInfo is process enrichment. Populated only when a rule or the
// collector requires it.
type ProcInfo struct {
	Exe         string        `json:"exe,omitempty"`
	Cmdline     []string      `json:"cmdline,omitempty"`
	Environ     []string      `json:"environ,omitempty"`
	MapsLibs    []string      `json:"maps_libs,omitempty"`
	CapEff      uint64        `json:"cap_eff,omitempty"`
	ContainerID string        `json:"container_id,omitempty"`
	StartTicks  uint64        `json:"start_ticks,omitempty"`
	Namespaces  *NamespaceIDs `json:"namespaces,omitempty"`
}

// NetInfo is network enrichment.
type NetInfo struct {
	Family     uint8  `json:"family,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	State      string `json:"state,omitempty"`
}

// FileInfo is file enrichment.
type FileInfo struct {
	Path   string `json:"path,omitempty"`
	Op     string `json:"op,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
	Device uint64 `json:"device,omitempty"`
}

// Event is the canonical unit flowing through the pipeline.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	Kind          Kind      `json:"kind"`
	Time          time.Time `json:"time"`

	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid,omitempty"`
	PPID uint32 `json:"ppid,omitempty"`
	UID  uint32 `json:"uid,omitempty"`
	EUID uint32 `json:"euid,omitempty"`
	Comm string `json:"comm,omitempty"`
	Host string `json:"host,omitempty"`

	Proc   *ProcInfo      `json:"proc,omitempty"`
	Net    *NetInfo       `json:"net,omitempty"`
	File   *FileInfo      `json:"file,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`

	Chain *ChainMeta `json:"chain,omitempty"`
}

// Normalize fills defaults that all producers must agree on.
func (e *Event) Normalize() {
	if e.SchemaVersion == "" {
		e.SchemaVersion = SchemaVersion
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
}
