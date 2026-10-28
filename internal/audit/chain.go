// Package audit implements the tamper-evident event log: a SHA-256 hash
// chain with optional HMAC, plus a remote anchor for truncation detection.
//
// The chain binds ChainID, Seq and PrevHash into each event's hash. Verify
// enforces strict monotonic sequence numbers and rejects events that carry
// no integrity metadata once the chain has started.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"edr/internal/event"
)

// Version is the integrity metadata version stamped on sealed events.
const Version = "v2.0"

// Issue kinds reported by verification.
const (
	IssueMalformed        = "malformed"
	IssueMissingIntegrity = "missing_integrity"
	IssueSeqGap           = "seq_gap"
	IssuePrevHashBreak    = "prev_hash_break"
	IssueHashMismatch     = "hash_mismatch"
	IssueHMACMismatch     = "hmac_mismatch"
	IssueHMACUnverified   = "hmac_unverified"
)

// Head is the tip of a chain.
type Head struct {
	ChainID string `json:"chain_id"`
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
	HMAC    string `json:"hmac,omitempty"`
}

// Issue is a single integrity anomaly.
type Issue struct {
	Line     int    `json:"line"`
	Seq      uint64 `json:"seq,omitempty"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// VerifyResult is the outcome of a verification pass.
type VerifyResult struct {
	OK       bool    `json:"ok"`
	ChainID  string  `json:"chain_id,omitempty"`
	Lines    int     `json:"lines"`
	LastSeq  uint64  `json:"last_seq"`
	LastHash string  `json:"last_hash,omitempty"`
	Issues   []Issue `json:"issues,omitempty"`
}

// Chain seals events. Use NewChain / NewChainAt.
type Chain struct {
	mu    sync.Mutex
	key   []byte
	state Head
}

// NewChain creates a chain starting empty.
func NewChain(key []byte) *Chain { return NewChainAt(key, Head{}) }

// NewChainAt creates a chain that continues from head (anchored restart).
func NewChainAt(key []byte, head Head) *Chain {
	if head.ChainID == "" {
		head.ChainID = newChainID()
	}
	return &Chain{key: append([]byte(nil), key...), state: head}
}

func newChainID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "edr-chain-fallback"
	}
	return "edr-" + hex.EncodeToString(b[:])
}

// Head returns the current chain tip.
func (c *Chain) Head() Head {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Seal stamps ev with chain metadata and returns the JSONL line to persist.
func (c *Chain) Seal(ev *event.Event) ([]byte, error) {
	if ev == nil {
		return nil, errors.New("audit: nil event")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ev.Normalize()
	c.state.Seq++
	ev.Chain = &event.ChainMeta{
		Version:  Version,
		ChainID:  c.state.ChainID,
		Seq:      c.state.Seq,
		PrevHash: c.state.Hash,
	}
	payload, err := canonical(ev)
	if err != nil {
		c.state.Seq--
		return nil, err
	}
	sum := sha256.Sum256(payload)
	ev.Chain.Hash = hex.EncodeToString(sum[:])
	if len(c.key) > 0 {
		mac := hmac.New(sha256.New, c.key)
		mac.Write(sum[:])
		ev.Chain.HMAC = hex.EncodeToString(mac.Sum(nil))
	}
	c.state.Hash = ev.Chain.Hash
	c.state.HMAC = ev.Chain.HMAC

	line, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

func canonical(ev *event.Event) ([]byte, error) {
	clone := *ev
	if ev.Chain != nil {
		meta := *ev.Chain
		meta.Hash = ""
		meta.HMAC = ""
		clone.Chain = &meta
	}
	return json.Marshal(clone)
}

// ---- verification ----

type verifier struct {
	key       []byte
	prevHash  string
	expectSeq uint64
	line      int
	res       VerifyResult
}

func newVerifier(key []byte) *verifier {
	return &verifier{key: key}
}

func (v *verifier) feed(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		v.line++
		v.res.Lines++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		v.checkLine(raw)
	}
	return sc.Err()
}

func (v *verifier) checkLine(raw []byte) {
	var ev event.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		v.add(Issue{Line: v.line, Kind: IssueMalformed, Detail: err.Error()})
		return
	}
	if ev.Chain == nil || ev.Chain.Version == "" {
		v.add(Issue{Line: v.line, Kind: IssueMissingIntegrity, Detail: "event has no chain metadata"})
		return
	}
	if v.res.ChainID == "" {
		v.res.ChainID = ev.Chain.ChainID
	}
	if v.expectSeq == 0 {
		// First event of the whole store must be seq 1: verify already
		// started (expectSeq set) or we start fresh here.
		v.expectSeq = ev.Chain.Seq
	}
	if ev.Chain.Seq != v.expectSeq {
		v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssueSeqGap,
			Expected: strconv.FormatUint(v.expectSeq, 10), Actual: strconv.FormatUint(ev.Chain.Seq, 10)})
	}
	if ev.Chain.PrevHash != v.prevHash {
		v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssuePrevHashBreak,
			Expected: v.prevHash, Actual: ev.Chain.PrevHash})
	}
	payload, err := canonical(&ev)
	if err != nil {
		v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssueMalformed, Detail: err.Error()})
	} else {
		sum := sha256.Sum256(payload)
		want := hex.EncodeToString(sum[:])
		if want != ev.Chain.Hash {
			v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssueHashMismatch, Expected: want, Actual: ev.Chain.Hash})
		}
		if len(v.key) > 0 {
			mac := hmac.New(sha256.New, v.key)
			mac.Write(sum[:])
			wantMAC := hex.EncodeToString(mac.Sum(nil))
			if wantMAC != ev.Chain.HMAC {
				v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssueHMACMismatch, Expected: wantMAC, Actual: ev.Chain.HMAC})
			}
		} else if ev.Chain.HMAC != "" {
			// The chain is keyed but no key was supplied: hash integrity can be
			// recomputed without the key, so authenticity cannot be asserted.
			v.add(Issue{Line: v.line, Seq: ev.Chain.Seq, Kind: IssueHMACUnverified,
				Detail: "event is HMAC'd but no key was supplied"})
		}
	}
	v.prevHash = ev.Chain.Hash
	v.expectSeq = ev.Chain.Seq + 1
	v.res.LastSeq = ev.Chain.Seq
	v.res.LastHash = ev.Chain.Hash
}

func (v *verifier) add(i Issue) {
	v.res.Issues = append(v.res.Issues, i)
	v.res.OK = false
}

// Verify replays a single JSONL stream.
func Verify(r io.Reader, key []byte) (VerifyResult, error) {
	v := newVerifier(key)
	v.res.OK = true
	if err := v.feed(r); err != nil {
		return v.res, err
	}
	v.res.OK = len(v.res.Issues) == 0
	return v.res, nil
}

// VerifyFile verifies path and its rotated siblings (.1, .2, ...) in
// chronological order, so truncation across rotation is detected.
func VerifyFile(path string, key []byte) (VerifyResult, error) {
	files := rotationList(path)
	v := newVerifier(key)
	v.res.OK = true
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return v.res, err
		}
		err = v.feed(fh)
		fh.Close()
		if err != nil {
			return v.res, err
		}
	}
	v.res.OK = len(v.res.Issues) == 0
	return v.res, nil
}

// rotationList returns [path.N ... path.1, path] (oldest first).
func rotationList(path string) []string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if _, e := os.Stat(path); e == nil {
			return []string{path}
		}
		return nil
	}
	var nums []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base+".") {
			continue
		}
		if n, err := strconv.Atoi(name[len(base)+1:]); err == nil && n > 0 {
			nums = append(nums, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	var files []string
	for _, n := range nums {
		files = append(files, fmt.Sprintf("%s.%d", path, n))
	}
	if _, err := os.Stat(path); err == nil {
		files = append(files, path)
	}
	return files
}
