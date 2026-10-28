package protect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeReader struct {
	hb  uint64
	pid uint32
	err error
}

func (f *fakeReader) ReadHeartbeat() (uint64, error) { return f.hb, f.err }
func (f *fakeReader) ReadAgentPID() (uint32, error)  { return f.pid, f.err }

func TestSentinelOKThenStale(t *testing.T) {
	r := &fakeReader{hb: 100, pid: 42}
	s := NewSentinel(Config{Reader: r, AgentPID: 42})
	if ok, why := s.Check(); !ok {
		t.Fatalf("first check should be ok: %s", why)
	}
	// heartbeat unchanged on the next check => stale
	if ok, why := s.Check(); ok {
		t.Fatalf("stale heartbeat not detected: %s", why)
	}
	// heartbeat advances again => ok
	r.hb = 200
	s2 := NewSentinel(Config{Reader: r, AgentPID: 42})
	s2.Check()
	r.hb = 300
	if ok, why := s2.Check(); !ok {
		t.Fatalf("fresh heartbeat should be ok: %s", why)
	}
}

func TestSentinelDetectsPIDTamper(t *testing.T) {
	r := &fakeReader{hb: 1, pid: 999}
	s := NewSentinel(Config{Reader: r, AgentPID: 42})
	if ok, why := s.Check(); ok {
		t.Fatal("agent_pid tamper not detected")
	} else if why == "" {
		t.Fatal("expected a reason")
	}
}

func TestSentinelReadError(t *testing.T) {
	r := &fakeReader{err: errors.New("boom")}
	s := NewSentinel(Config{Reader: r, AgentPID: 42})
	if ok, _ := s.Check(); ok {
		t.Fatal("read error must fail the check")
	}
}

func TestSentinelDetectsBinaryTamper(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "edr-agent")
	if err := os.WriteFile(bin, []byte("original"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{hb: 1, pid: 42}
	// HashEvery 0 would coalesce; force a re-hash by changing size/content.
	s := NewSentinel(Config{Reader: r, AgentPID: 42, BinaryPath: bin})
	if ok, why := s.Check(); !ok {
		t.Fatalf("untampered binary should pass: %s", why)
	}
	if err := os.WriteFile(bin, []byte("replaced-with-longer-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.hb = 2 // keep the heartbeat fresh
	if ok, why := s.Check(); ok {
		t.Fatalf("binary tamper not detected: %s", why)
	}
}

func TestSentinelDetectsMissingResources(t *testing.T) {
	dir := t.TempDir()
	r := &fakeReader{hb: 1, pid: 42}
	s := NewSentinel(Config{
		Reader:         r,
		AgentPID:       42,
		InstallDir:     filepath.Join(dir, "does-not-exist"),
		DatapathSocket: filepath.Join(dir, "datapath.sock"),
	})
	if ok, why := s.Check(); ok {
		t.Fatalf("missing install dir not detected: %s", why)
	}
}
