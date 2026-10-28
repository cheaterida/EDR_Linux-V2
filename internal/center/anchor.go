package center

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// anchorRecord mirrors audit.AnchorRecord on the wire. It is stored off-host so
// a local attacker cannot rewrite the trusted chain head.
type anchorRecord struct {
	ChainID  string    `json:"chain_id"`
	Seq      uint64    `json:"seq"`
	Hash     string    `json:"hash"`
	PushedAt time.Time `json:"pushed_at"`
}

func (s *Store) anchorPath(host string) string {
	return filepath.Join(s.hostDir(host), "anchor.json")
}

// SaveAnchor persists the anchor for a host.
func (s *Store) SaveAnchor(host string, rec anchorRecord) error {
	dir := s.hostDir(host)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := s.anchorPath(host) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.anchorPath(host))
}

// LoadAnchor returns the stored anchor for a host.
func (s *Store) LoadAnchor(host string) (anchorRecord, bool) {
	raw, err := os.ReadFile(s.anchorPath(host))
	if err != nil {
		return anchorRecord{}, false
	}
	var rec anchorRecord
	if json.Unmarshal(raw, &rec) != nil {
		return anchorRecord{}, false
	}
	if rec.ChainID == "" || rec.Seq == 0 {
		return anchorRecord{}, false
	}
	return rec, true
}
