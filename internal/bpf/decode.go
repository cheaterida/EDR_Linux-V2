package bpf

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"edr/internal/event"
)

// RecordSize is the fixed size of struct edr_event (see probes/common.h).
// The C side asserts this with _Static_assert.
const RecordSize = 592

// Field offsets in the ring-buffer record (little-endian). Kept in one place
// so a layout change is a one-line edit here plus the C assert.
const (
	offTS       = 0   // u64
	offPID      = 8   // u32 (tgid)
	offTID      = 12  // u32
	offPPID     = 16  // u32
	offUID      = 20  // u32
	offReserved = 24  // u32
	offFileOp   = 28  // u32
	offType     = 32  // u8
	offFamily   = 33  // u8
	offDPort    = 36  // u16
	offDaddrV4  = 40  // u32
	offDaddrV6  = 44  // u8[16]
	offComm     = 60  // char[16]
	offFilename = 76  // char[256]
	offCmdline  = 332 // char[256] (exec only, NUL-separated argv)
)

// decodeRecord converts a raw ring-buffer record into an event.Event.
// Returns false if the record is too short.
func decodeRecord(raw []byte) (event.Event, bool) {
	if len(raw) < RecordSize {
		return event.Event{}, false
	}
	var ev event.Event
	kind := event.Kind(raw[offType])
	ev.Kind = kind

	// ts_ns is bpf_ktime_get_ns(): monotonic-since-boot, NOT wall clock.
	// We timestamp with userspace receive time and keep the raw value for
	// correlation (avoids the v0.9 mistake of treating it as epoch time).
	ev.Time = time.Now().UTC()
	ev.Detail = map[string]any{"ts_ns": binary.LittleEndian.Uint64(raw[offTS : offTS+8])}

	ev.PID = binary.LittleEndian.Uint32(raw[offPID : offPID+4])
	ev.TGID = ev.PID
	ev.PPID = binary.LittleEndian.Uint32(raw[offPPID : offPPID+4])
	ev.UID = binary.LittleEndian.Uint32(raw[offUID : offUID+4])
	ev.Comm = cstr(raw[offComm : offComm+16])

	switch kind {
	case event.KindExec:
		ev.Proc = &event.ProcInfo{
			Exe:     cstr(raw[offFilename : offFilename+256]),
			Cmdline: splitNul(raw[offCmdline : offCmdline+256]),
		}
	case event.KindFileOp:
		ev.File = &event.FileInfo{
			Path: cstr(raw[offFilename : offFilename+256]),
			Op:   fileOpName(binary.LittleEndian.Uint32(raw[offFileOp : offFileOp+4])),
		}
	case event.KindConnect:
		family := raw[offFamily]
		netInfo := &event.NetInfo{
			Family:     family,
			RemotePort: binary.LittleEndian.Uint16(raw[offDPort : offDPort+2]),
			Protocol:   "tcp",
		}
		switch family {
		case 2: // AF_INET
			v4 := binary.LittleEndian.Uint32(raw[offDaddrV4 : offDaddrV4+4])
			netInfo.RemoteAddr = net.IPv4(byte(v4), byte(v4>>8), byte(v4>>16), byte(v4>>24)).String()
		case 10: // AF_INET6
			netInfo.RemoteAddr = net.IP(raw[offDaddrV6 : offDaddrV6+16]).String()
		}
		ev.Net = netInfo
	case event.KindPrivesc:
		sub := binary.LittleEndian.Uint32(raw[offReserved : offReserved+4])
		ev.Detail["privtype"] = privTypeName(sub)
		ev.Detail["value"] = binary.LittleEndian.Uint32(raw[offFileOp : offFileOp+4])
	case event.KindModuleLoad, event.KindModuleUnload:
		ev.Detail["module"] = cstr(raw[offFilename : offFilename+256])
		ev.Detail["subtype"] = binary.LittleEndian.Uint32(raw[offReserved : offReserved+4])
	case event.KindBPFOp:
		ev.Detail["bpf_cmd"] = binary.LittleEndian.Uint32(raw[offReserved : offReserved+4])
	case event.KindSelfProtect:
		ev.Detail["syscall"] = cstr(raw[offFilename : offFilename+256])
		ev.Detail["detail"] = binary.LittleEndian.Uint32(raw[offReserved : offReserved+4])
		ev.Detail["target_pid"] = ev.PPID
	}

	ev.Normalize()
	return ev, true
}

// DecodeRecord is the exported form of decodeRecord, for tests and for
// consumers that receive raw ring-buffer samples.
func DecodeRecord(raw []byte) (event.Event, bool) { return decodeRecord(raw) }

func fileOpName(op uint32) string {
	switch op {
	case 1:
		return "unlinkat"
	case 2:
		return "unlink"
	case 3:
		return "renameat"
	case 4:
		return "vfs_unlink"
	case 5:
		return "vfs_rename"
	case 6:
		return "vfs_rename_to"
	}
	return "unknown"
}

func privTypeName(sub uint32) string {
	switch sub {
	case 1:
		return "setuid"
	case 2:
		return "setgid"
	case 3:
		return "capset"
	}
	return "unknown"
}

// cstr returns the NUL-terminated prefix of b as a string.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// splitNul reconstructs argv from a fixed buffer holding NUL-separated strings
// (captured in-kernel), dropping empty/trailing segments.
func splitNul(b []byte) []string {
	var out []string
	for _, p := range strings.Split(string(b), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
