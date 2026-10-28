// Package lease implements a single-writer lease stored as a file, used to
// guarantee that only one HA peer restarts a failed instance at a time
// (split-brain prevention).
package lease

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Lease is the on-disk record.
type Lease struct {
	Target     string    `json:"target"`
	Holder     string    `json:"holder"`
	LeaseID    string    `json:"lease_id"`
	RequestID  string    `json:"request_id,omitempty"`
	Source     string    `json:"source,omitempty"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ErrHeld indicates the lease is held by another live holder.
var ErrHeld = errors.New("lease held by another holder")

func path(runDir, target string) string {
	return filepath.Join(runDir, target+".lease")
}

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "lease-fallback"
	}
	return hex.EncodeToString(b[:])
}

// Read returns the lease for target, if any.
func Read(runDir, target string) (Lease, error) {
	var l Lease
	raw, err := os.ReadFile(path(runDir, target))
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, err
	}
	return l, nil
}

// Acquire takes the lease for target on behalf of holder. It fails with
// ErrHeld when a non-expired lease is held by another holder.
func Acquire(runDir, target, holder string, ttl time.Duration, now time.Time) (Lease, error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return Lease{}, err
	}
	if cur, err := Read(runDir, target); err == nil {
		if now.Before(cur.ExpiresAt) {
			if cur.Holder == holder {
				// Refresh our own lease.
				return writeLease(runDir, cur, now, ttl)
			}
			return Lease{}, ErrHeld
		}
	}
	return writeLease(runDir, Lease{Target: target, Holder: holder, Generation: 1}, now, ttl)
}

// Release removes the lease if leaseID matches.
func Release(runDir, target, leaseID string) error {
	cur, err := Read(runDir, target)
	if err != nil {
		return err
	}
	if leaseID != "" && cur.LeaseID != leaseID {
		return ErrHeld
	}
	return os.Remove(path(runDir, target))
}

func writeLease(runDir string, l Lease, now time.Time, ttl time.Duration) (Lease, error) {
	l.LeaseID = newID()
	l.ExpiresAt = now.Add(ttl)
	raw, err := json.Marshal(l)
	if err != nil {
		return Lease{}, err
	}
	p := path(runDir, l.Target)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return Lease{}, err
	}
	if err := os.Rename(tmp, p); err != nil {
		return Lease{}, err
	}
	return l, nil
}
