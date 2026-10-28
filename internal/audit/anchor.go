package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"edr/internal/requestauth"
)

// AnchorRecord is what gets pushed to a remote/mirror anchor.
type AnchorRecord struct {
	Head
	PushedAt time.Time `json:"pushed_at"`
}

// Anchor stores the latest chain head outside the local log so that
// truncation by a local attacker can be detected. Backends: in-memory (test),
// file mirror, or HTTP endpoint.
type Anchor struct {
	mu       sync.Mutex
	url      string
	filePath string
	client   *http.Client
	auth     *requestauth.Authenticator
	lastSeq  uint64
	mem      *Head
}

// AnchorOptions configures a file/HTTP anchor. Secret, when set, HMAC-signs
// remote anchor requests and verifies signed responses (center anchor).
type AnchorOptions struct {
	URL      string
	FilePath string
	Secret   []byte
}

// NewAnchor returns a purely in-memory anchor (tests / single process).
func NewAnchor() *Anchor { return &Anchor{} }

// NewAnchorWithOptions returns an anchor backed by a file mirror and/or an
// HTTP endpoint, or nil when neither is configured.
func NewAnchorWithOptions(opts AnchorOptions) *Anchor {
	if opts.URL == "" && opts.FilePath == "" {
		return nil
	}
	a := &Anchor{
		url:      opts.URL,
		filePath: opts.FilePath,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
	if len(opts.Secret) > 0 {
		a.auth = requestauth.New(opts.Secret, 60*time.Second)
	}
	return a
}

// Push records head to every configured backend. seq 0 is ignored.
func (a *Anchor) Push(head Head) error {
	if a == nil || head.Seq == 0 {
		return nil
	}
	a.mu.Lock()
	if head.Seq <= a.lastSeq {
		a.mu.Unlock()
		return nil
	}
	a.lastSeq = head.Seq
	a.mu.Unlock()

	rec := AnchorRecord{Head: head, PushedAt: time.Now().UTC()}
	var firstErr error
	if a.filePath != "" {
		if err := a.pushFile(rec); err != nil {
			firstErr = err
		}
	}
	if a.url != "" {
		if err := a.pushHTTP(rec); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.filePath == "" && a.url == "" {
		cp := head
		a.mu.Lock()
		a.mem = &cp
		a.mu.Unlock()
	}
	return firstErr
}

// Fetch returns the last anchored head.
func (a *Anchor) Fetch() (*Head, bool) {
	if a == nil {
		return nil, false
	}
	if a.filePath != "" {
		if h, ok := a.fetchFile(); ok {
			return h, true
		}
	}
	if a.url != "" {
		if h, ok := a.fetchHTTP(); ok {
			return h, true
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mem == nil {
		return nil, false
	}
	cp := *a.mem
	return &cp, true
}

// FetchStrict is like Fetch but treats an existing-but-corrupt/unreadable local
// anchor file as an error instead of silently starting a fresh chain. Without
// this, an attacker who corrupts the anchor could make the agent abandon its
// continuity anchor without notice (fail-open).
func (a *Anchor) FetchStrict() (*Head, bool, error) {
	if a == nil {
		return nil, false, nil
	}
	if a.filePath != "" {
		raw, err := os.ReadFile(a.filePath)
		switch {
		case err == nil:
			var rec AnchorRecord
			if uerr := json.Unmarshal(raw, &rec); uerr != nil {
				return nil, false, fmt.Errorf("anchor file %s corrupt: %w", a.filePath, uerr)
			}
			if rec.ChainID == "" || rec.Seq == 0 {
				return nil, false, fmt.Errorf("anchor file %s invalid (empty head)", a.filePath)
			}
			h := rec.Head
			return &h, true, nil
		case os.IsNotExist(err):
			// First start: fall through to the other backends.
		default:
			return nil, false, fmt.Errorf("anchor file %s unreadable: %w", a.filePath, err)
		}
	}
	h, ok := a.Fetch()
	return h, ok, nil
}

// CrossVerify compares a local head against the anchor.
func (a *Anchor) CrossVerify(local Head) []Issue {
	rec, ok := a.Fetch()
	if !ok {
		return nil
	}
	var issues []Issue
	if rec.ChainID != "" && local.ChainID != "" && rec.ChainID != local.ChainID {
		issues = append(issues, Issue{Kind: "anchor_chain_mismatch", Expected: local.ChainID, Actual: rec.ChainID})
	}
	if rec.Seq > local.Seq {
		issues = append(issues, Issue{
			Kind: "anchor_truncation", Seq: rec.Seq,
			Detail:   "anchor has more events than local log",
			Expected: fmt.Sprintf("%d", rec.Seq), Actual: fmt.Sprintf("%d", local.Seq),
		})
	}
	if rec.Seq == local.Seq && rec.Hash != "" && local.Hash != "" && rec.Hash != local.Hash {
		issues = append(issues, Issue{
			Kind: "anchor_hash_mismatch", Seq: rec.Seq,
			Expected: local.Hash, Actual: rec.Hash,
		})
	}
	return issues
}

func (a *Anchor) pushFile(rec AnchorRecord) error {
	if err := os.MkdirAll(filepath.Dir(a.filePath), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := a.filePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.filePath)
}

func (a *Anchor) fetchFile() (*Head, bool) {
	raw, err := os.ReadFile(a.filePath)
	if err != nil {
		return nil, false
	}
	var rec AnchorRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, false
	}
	cp := rec.Head
	return &cp, true
}

func (a *Anchor) pushHTTP(rec AnchorRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, a.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.auth != nil {
		a.auth.Sign(req, raw, "", time.Now().UTC())
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("anchor push: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *Anchor) fetchHTTP() (*Head, bool) {
	req, err := http.NewRequest(http.MethodGet, a.url, nil)
	if err != nil {
		return nil, false
	}
	if a.auth != nil {
		a.auth.Sign(req, nil, "", time.Now().UTC())
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if a.auth != nil {
		// Reject an unauthenticated/forged anchor: a MITM returning a lower
		// head could otherwise hide truncation.
		if err := a.auth.VerifyBody(body, resp.Header.Get(requestauth.HeaderResponseSignature)); err != nil {
			return nil, false
		}
	}
	var rec AnchorRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, false
	}
	cp := rec.Head
	return &cp, true
}
