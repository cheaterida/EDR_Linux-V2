// Package requestauth signs and verifies HA HTTP requests with HMAC-SHA256
// and rejects replayed request IDs.
package requestauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	HeaderSignature         = "X-EDR-Signature"
	HeaderRequestID         = "X-EDR-Request-ID"
	HeaderTimestamp         = "X-EDR-Timestamp"
	HeaderResponseSignature = "X-EDR-Response-Signature"
)

// Authenticator verifies and produces request signatures.
type Authenticator struct {
	secret []byte
	window time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

// New builds an Authenticator. A nil/empty secret disables auth (fail-open is
// the caller's explicit choice: peers that configure a secret get enforcement).
func New(secret []byte, window time.Duration) *Authenticator {
	if window <= 0 {
		window = 30 * time.Second
	}
	return &Authenticator{secret: append([]byte(nil), secret...), window: window, seen: map[string]time.Time{}}
}

// Enabled reports whether a secret is configured.
func (a *Authenticator) Enabled() bool { return a != nil && len(a.secret) > 0 }

// Sign attaches auth headers to req.
func (a *Authenticator) Sign(req *http.Request, body []byte, requestID string, ts time.Time) {
	if !a.Enabled() {
		return
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts.UTC().Format(time.RFC3339Nano))
	req.Header.Set(HeaderSignature, "sha256="+a.sign(req.Method, req.URL.RequestURI(), body, requestID, ts))
}

// SignBody returns a signature for a response body. Agents verify it so that an
// on-path attacker cannot inject response content (notably destructive actions).
func (a *Authenticator) SignBody(body []byte) string {
	if !a.Enabled() {
		return ""
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte("response\n"))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyBody checks a response body against its signature header.
func (a *Authenticator) VerifyBody(body []byte, sig string) error {
	if !a.Enabled() {
		return nil
	}
	if sig == "" {
		return errors.New("missing response signature")
	}
	want := a.SignBody(body)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("bad response signature")
	}
	return nil
}

// Authorize verifies the request signature and rejects replays.
func (a *Authenticator) Authorize(req *http.Request, body []byte) error {
	if !a.Enabled() {
		return nil
	}
	requestID := strings.TrimSpace(req.Header.Get(HeaderRequestID))
	tsRaw := strings.TrimSpace(req.Header.Get(HeaderTimestamp))
	sig := strings.TrimSpace(req.Header.Get(HeaderSignature))
	if requestID == "" || tsRaw == "" || sig == "" {
		return errors.New("missing auth headers")
	}
	ts, err := time.Parse(time.RFC3339Nano, tsRaw)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	if d := time.Since(ts); d > a.window || d < -a.window {
		return errors.New("stale request")
	}
	expected := "sha256=" + a.sign(req.Method, req.URL.RequestURI(), body, requestID, ts)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return errors.New("bad signature")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.seen[requestID]; ok && time.Since(t) <= a.window {
		return errors.New("replayed request")
	}
	a.seen[requestID] = ts
	return nil
}

func (a *Authenticator) sign(method, path string, body []byte, requestID string, ts time.Time) string {
	mac := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(mac, "%s\n%s\n%d\n%s\n", method, path, ts.UnixNano(), requestID)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
