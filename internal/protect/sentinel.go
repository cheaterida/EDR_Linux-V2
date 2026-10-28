// Package protect wires the agent's self-protection: it registers the agent
// pid and its own BPF objects, and runs a sentinel that detects when the BPF
// probes, the agent_pid map, the agent binary or supporting resources have
// been tampered with.
package protect

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"time"
)

// Reader is the minimal view of the BPF loader the sentinel needs.
type Reader interface {
	ReadHeartbeat() (uint64, error)
	ReadAgentPID() (uint32, error)
}

// Config configures the sentinel. Only Reader and AgentPID are required; each
// optional check is skipped when its field is empty.
type Config struct {
	Reader         Reader
	AgentPID       uint32
	BinaryPath     string        // agent executable; hashed at startup
	InstallDir     string        // optional; checked for existence
	DatapathSocket string        // optional; checked for existence
	HashEvery      time.Duration // force a full re-hash at least this often (0 => 5m)
}

// Sentinel detects probe detachment (stale heartbeat), agent_pid tampering,
// binary replacement and removal of supporting files/resources.
type Sentinel struct {
	cfg Config

	last   uint64
	checks int

	startupHash [32]byte
	haveHash    bool
	statSize    int64
	statMod     time.Time
	lastHashAt  time.Time
}

// NewSentinel builds a sentinel and records the startup binary hash.
func NewSentinel(cfg Config) *Sentinel {
	if cfg.HashEvery <= 0 {
		cfg.HashEvery = 5 * time.Minute
	}
	s := &Sentinel{cfg: cfg}
	if cfg.BinaryPath != "" {
		if data, err := os.ReadFile(cfg.BinaryPath); err == nil {
			s.startupHash = sha256.Sum256(data)
			s.haveHash = true
			s.lastHashAt = time.Now()
			if st, err := os.Stat(cfg.BinaryPath); err == nil {
				s.statSize = st.Size()
				s.statMod = st.ModTime()
			}
		}
	}
	return s
}

// Check returns (ok, reason). It verifies the agent_pid map, the BPF heartbeat,
// the agent binary (cheap stat fast-path; full hash on change or every
// HashEvery) and, when configured, that the install dir and datapath socket
// still exist. The caller must drive the heartbeat by invoking a raw getpid()
// between checks, otherwise a stale reading is expected and actionable.
func (s *Sentinel) Check() (bool, string) {
	if s.cfg.Reader == nil {
		return true, "no reader configured"
	}
	pid, err := s.cfg.Reader.ReadAgentPID()
	if err != nil {
		return false, fmt.Sprintf("agent_pid map unreadable: %v", err)
	}
	if pid != s.cfg.AgentPID {
		return false, fmt.Sprintf("agent_pid map tampered (got %d, want %d)", pid, s.cfg.AgentPID)
	}
	hb, err := s.cfg.Reader.ReadHeartbeat()
	if err != nil {
		return false, fmt.Sprintf("heartbeat map unreadable: %v", err)
	}
	if s.checks > 0 && hb == s.last {
		return false, "heartbeat stale — probes may be detached"
	}
	s.last = hb
	if ok, why := s.checkBinary(); !ok {
		return false, why
	}
	if s.cfg.InstallDir != "" {
		if _, err := os.Stat(s.cfg.InstallDir); err != nil {
			return false, fmt.Sprintf("install dir %s missing: %v", s.cfg.InstallDir, err)
		}
	}
	if s.cfg.DatapathSocket != "" {
		// A stale socket file survives a killed datapath, so probe liveness by
		// connecting rather than just stat-ing the path.
		conn, err := net.DialTimeout("unix", s.cfg.DatapathSocket, 300*time.Millisecond)
		if err != nil {
			return false, fmt.Sprintf("datapath %s unreachable: %v", s.cfg.DatapathSocket, err)
		}
		_ = conn.Close()
	}
	s.checks++
	return true, "ok"
}

// checkBinary uses a stat fast-path and only re-hashes when the file changed or
// the force-hash interval elapsed, keeping the steady-state cost negligible.
func (s *Sentinel) checkBinary() (bool, string) {
	if s.cfg.BinaryPath == "" || !s.haveHash {
		return true, ""
	}
	st, err := os.Stat(s.cfg.BinaryPath)
	if err != nil {
		return false, fmt.Sprintf("agent binary missing: %v", err)
	}
	unchanged := st.Size() == s.statSize && st.ModTime().Equal(s.statMod)
	if unchanged && time.Since(s.lastHashAt) < s.cfg.HashEvery {
		return true, ""
	}
	data, err := os.ReadFile(s.cfg.BinaryPath)
	if err != nil {
		return false, fmt.Sprintf("agent binary unreadable: %v", err)
	}
	sum := sha256.Sum256(data)
	s.statSize, s.statMod, s.lastHashAt = st.Size(), st.ModTime(), time.Now()
	if sum != s.startupHash {
		return false, "agent binary modified since startup"
	}
	return true, ""
}

// Checks returns how many successful checks have run.
func (s *Sentinel) Checks() int { return s.checks }
