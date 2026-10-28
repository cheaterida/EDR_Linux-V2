// Package adminauth issues and verifies short-lived HMAC bearer tokens for
// privileged control-plane actions. Tokens are bound to an action and a
// timestamp, and are rejected on replay (the server records used nonces).
package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	KeyLen       = 32
	TokenValid   = 300 * time.Second
	MaxClockSkew = 30 * time.Second
	minKeyBytes  = 16
)

var (
	ErrInvalidToken = errors.New("invalid admin token")
	ErrExpired      = errors.New("admin token expired")
	ErrReplayed     = errors.New("admin token replayed")
	ErrKeyNotSet    = errors.New("admin key not configured")
)

var validActions = map[string]bool{
	"shutdown":       true,
	"restart":        true,
	"policy-reload":  true,
	"enforce-toggle": true,
}

// GenerateKey returns a fresh 32-byte key.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncodeKey returns the hex form for CLI use.
func EncodeKey(key []byte) string { return hex.EncodeToString(key) }

// LoadOrCreateKey reads a hex key file, generating and persisting one if
// missing. Returns (nil, nil) when path is empty.
func LoadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if raw, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err == nil && len(key) >= minKeyBytes {
			if len(key) < KeyLen {
				padded := make([]byte, KeyLen)
				copy(padded, key)
				return padded, nil
			}
			return key[:KeyLen], nil
		}
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(EncodeKey(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Auth verifies tokens and remembers used nonces for replay protection.
type Auth struct {
	mu   sync.Mutex
	key  []byte
	seen map[string]time.Time
}

// New returns an Auth. A nil/short key disables it.
func New(key []byte) *Auth {
	return &Auth{key: append([]byte(nil), key...), seen: map[string]time.Time{}}
}

// Enabled reports whether a usable key is configured.
func (a *Auth) Enabled() bool { return a != nil && len(a.key) >= minKeyBytes }

func sign(key []byte, action string, ts int64, nonce string) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s:%d:%s", action, ts, nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

// Issue creates a token for action.
func (a *Auth) Issue(action string, now time.Time) (string, int64, error) {
	if !a.Enabled() {
		return "", 0, ErrKeyNotSet
	}
	if !validActions[action] {
		return "", 0, fmt.Errorf("unsupported action %q", action)
	}
	nb := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nb); err != nil {
		return "", 0, err
	}
	nonce := hex.EncodeToString(nb)
	ts := now.Unix()
	token := fmt.Sprintf("%s:%d:%s:%s", action, ts, nonce, sign(a.key, action, ts, nonce))
	return token, now.Add(TokenValid).Unix(), nil
}

// Verify validates a token for action and rejects replays.
func (a *Auth) Verify(token, action string, now time.Time) error {
	if !a.Enabled() {
		return ErrKeyNotSet
	}
	parts := strings.SplitN(token, ":", 4)
	if len(parts) != 4 {
		return ErrInvalidToken
	}
	tokenAction, tsStr, nonce, sig := parts[0], parts[1], parts[2], parts[3]
	if tokenAction != action {
		return ErrInvalidToken
	}
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		return ErrInvalidToken
	}
	age := now.Sub(time.Unix(ts, 0))
	if age > TokenValid+MaxClockSkew || age < -MaxClockSkew {
		return ErrExpired
	}
	if !hmac.Equal([]byte(sig), []byte(sign(a.key, action, ts, nonce))) {
		return ErrInvalidToken
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
	key := action + ":" + nonce
	if _, used := a.seen[key]; used {
		return ErrReplayed
	}
	a.seen[key] = now
	return nil
}

func (a *Auth) pruneLocked(now time.Time) {
	for k, t := range a.seen {
		if now.Sub(t) > TokenValid+MaxClockSkew {
			delete(a.seen, k)
		}
	}
}
