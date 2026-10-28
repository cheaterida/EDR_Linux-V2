// Package liveness reads and writes per-instance heartbeat files and derives
// a coarse health state from their age. It is the local half of the HA
// supervisor decision: the supervisor turns these states into quorum calls.
package liveness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Heartbeat is the on-disk record each instance publishes.
type Heartbeat struct {
	InstanceID        string `json:"instance_id"`
	Unix              int64  `json:"unix"`
	LeaseID           string `json:"lease_id,omitempty"`
	RestartGeneration uint64 `json:"restart_generation"`
}

// Path is the heartbeat file for an instance.
func Path(runDir, instanceID string) string {
	return filepath.Join(runDir, instanceID+".heartbeat")
}

// Write atomically persists hb under runDir.
func Write(runDir string, hb Heartbeat) error {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(hb)
	if err != nil {
		return err
	}
	p := Path(runDir, hb.InstanceID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Read loads an instance heartbeat.
func Read(runDir, instanceID string) (Heartbeat, error) {
	var hb Heartbeat
	raw, err := os.ReadFile(Path(runDir, instanceID))
	if err != nil {
		return hb, err
	}
	if err := json.Unmarshal(raw, &hb); err != nil {
		return hb, err
	}
	return hb, nil
}

// State classifies a heartbeat. suspectAfter/downAfter are multipliers of the
// nominal heartbeat interval. A missing heartbeat (zero time) is "starting".
func State(now time.Time, hb Heartbeat, suspectAfter, downAfter int, every time.Duration) string {
	if hb.Unix == 0 {
		return "starting"
	}
	if every <= 0 {
		every = time.Second
	}
	age := now.Sub(time.Unix(hb.Unix, 0))
	if age > time.Duration(downAfter)*every {
		return "down"
	}
	if age > time.Duration(suspectAfter)*every {
		return "suspect"
	}
	return "healthy"
}
