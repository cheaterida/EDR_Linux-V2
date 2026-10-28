package respond

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// QuarantineMeta records where a quarantined file came from.
type QuarantineMeta struct {
	OriginalPath string    `json:"original_path"`
	QuarantineAt time.Time `json:"quarantine_at"`
	Inode        uint64    `json:"inode"`
	Size         int64     `json:"size"`
	RuleID       string    `json:"rule_id,omitempty"`
	Name         string    `json:"name,omitempty"` // file name inside the quarantine dir
}

func (l *Local) quarantineDir() string {
	if l.QuarantineDir != "" {
		return l.QuarantineDir
	}
	return "/var/lib/edr/quarantine"
}

// ListQuarantine returns the metadata for all quarantined files.
func (l *Local) ListQuarantine() ([]QuarantineMeta, error) {
	dir := l.quarantineDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []QuarantineMeta
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".meta" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()+".meta"))
		if err != nil {
			continue
		}
		var m QuarantineMeta
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		m.Name = e.Name()
		out = append(out, m)
	}
	return out, nil
}

// RestoreQuarantine moves a quarantined file back to its original location.
func (l *Local) RestoreQuarantine(originalPath string) Result {
	if l.DryRun {
		return Result{Action: "quarantine_restore", Success: true, Enforced: false, Detail: "dry-run: would restore " + originalPath}
	}
	metas, err := l.ListQuarantine()
	if err != nil {
		return Result{Action: "quarantine_restore", Success: false, Detail: err.Error()}
	}
	dir := l.quarantineDir()
	for _, m := range metas {
		if m.OriginalPath != originalPath {
			continue
		}
		qPath := filepath.Join(dir, m.Name)
		if err := os.Chmod(qPath, 0o600); err != nil {
			return Result{Action: "quarantine_restore", Success: false, Detail: fmt.Sprintf("chmod: %v", err)}
		}
		if err := os.Rename(qPath, originalPath); err != nil {
			return Result{Action: "quarantine_restore", Success: false, Detail: fmt.Sprintf("rename: %v", err)}
		}
		_ = os.Remove(qPath + ".meta")
		return Result{Action: "quarantine_restore", Success: true, Enforced: true, Detail: "restored " + originalPath}
	}
	return Result{Action: "quarantine_restore", Success: false, Detail: "no quarantined file for " + originalPath}
}
