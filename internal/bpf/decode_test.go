package bpf

import (
	"encoding/binary"
	"testing"

	"edr/internal/event"
)

func newRecord() []byte { return make([]byte, RecordSize) }

func putStr(raw []byte, off int, s string) {
	copy(raw[off:], s)
}

func TestDecodeExec(t *testing.T) {
	raw := newRecord()
	raw[offType] = byte(event.KindExec)
	binary.LittleEndian.PutUint32(raw[offPID:], 1234)
	binary.LittleEndian.PutUint32(raw[offUID:], 0)
	putStr(raw, offComm, "bash")
	putStr(raw, offFilename, "/usr/bin/bash")

	ev, ok := decodeRecord(raw)
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Kind != event.KindExec {
		t.Fatalf("kind = %v", ev.Kind)
	}
	if ev.PID != 1234 || ev.Comm != "bash" {
		t.Fatalf("pid/comm = %d/%q", ev.PID, ev.Comm)
	}
	if ev.Proc == nil || ev.Proc.Exe != "/usr/bin/bash" {
		t.Fatalf("exe = %+v", ev.Proc)
	}
	if ev.Detail["ts_ns"] == nil {
		t.Fatal("ts_ns should be preserved in Detail")
	}
}

func TestDecodeConnectV4(t *testing.T) {
	raw := newRecord()
	raw[offType] = byte(event.KindConnect)
	raw[offFamily] = 2 // AF_INET
	binary.LittleEndian.PutUint16(raw[offDPort:], 4444)
	copy(raw[offDaddrV4:offDaddrV4+4], []byte{10, 0, 0, 1}) // network byte order

	ev, ok := decodeRecord(raw)
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Net == nil {
		t.Fatal("net info missing")
	}
	if ev.Net.RemoteAddr != "10.0.0.1" {
		t.Fatalf("remote addr = %q", ev.Net.RemoteAddr)
	}
	if ev.Net.RemotePort != 4444 {
		t.Fatalf("remote port = %d", ev.Net.RemotePort)
	}
}

func TestDecodeFileOp(t *testing.T) {
	raw := newRecord()
	raw[offType] = byte(event.KindFileOp)
	binary.LittleEndian.PutUint32(raw[offFileOp:], 1) // unlinkat
	putStr(raw, offFilename, "/tmp/dropper.sh")

	ev, ok := decodeRecord(raw)
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.File == nil || ev.File.Op != "unlinkat" || ev.File.Path != "/tmp/dropper.sh" {
		t.Fatalf("file = %+v", ev.File)
	}
}

func TestDecodeRejectsShortRecord(t *testing.T) {
	if _, ok := decodeRecord(make([]byte, 8)); ok {
		t.Fatal("short record should be rejected")
	}
}
