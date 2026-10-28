package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SigningKey is an Ed25519 key pair used to sign policy documents. The
// agent must only ever hold the public key.
type SigningKey struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateSigningKey creates a fresh key pair.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &SigningKey{Private: priv, Public: pub}, nil
}

// LoadSigningKey reads a hex-encoded private key (32-byte seed or 64-byte
// full key) from path.
func LoadSigningKey(path string) (*SigningKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	var seed []byte
	switch len(s) {
	case 64:
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		seed = b
	case 128:
		full, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		seed = full[:32]
	default:
		return nil, fmt.Errorf("signing key: expected 64 or 128 hex chars, got %d", len(s))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &SigningKey{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// SaveSigningKey writes the private key seed as hex with mode 0600.
func SaveSigningKey(key *SigningKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(key.Private.Seed())+"\n"), 0o600)
}

// LoadPublicKey reads a 32-byte (64 hex char) public key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	if len(s) != 64 {
		return nil, fmt.Errorf("public key: expected 64 hex chars, got %d", len(s))
	}
	pub, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return ed25519.PublicKey(pub), nil
}

// SavePublicKey writes a hex-encoded public key.
func SavePublicKey(pub ed25519.PublicKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// SignHex returns the hex-encoded Ed25519 signature over data.
func SignHex(key *SigningKey, data []byte) (string, error) {
	if key == nil || len(key.Private) == 0 {
		return "", errors.New("signing key is nil")
	}
	return hex.EncodeToString(ed25519.Sign(key.Private, data)), nil
}

// VerifyHex verifies a hex-encoded signature.
func VerifyHex(pub ed25519.PublicKey, data []byte, sigHex string) (bool, error) {
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false, fmt.Errorf("signature hex decode: %w", err)
	}
	return ed25519.Verify(pub, data, sig), nil
}

// SignatureFile is the conventional sidecar path for a signed document.
func SignatureFile(path string) string { return path + ".sig" }

// SignPolicy writes path+".sig" containing the signature over the raw policy
// bytes. The policy file itself is not modified.
func SignPolicy(key *SigningKey, policyPath string) error {
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	sig, err := SignHex(key, raw)
	if err != nil {
		return err
	}
	return os.WriteFile(SignatureFile(policyPath), []byte(sig+"\n"), 0o644)
}

// VerifyPolicyFile verifies policyPath against its .sig using pub.
func VerifyPolicyFile(pub ed25519.PublicKey, policyPath string) (bool, error) {
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return false, err
	}
	sigRaw, err := os.ReadFile(SignatureFile(policyPath))
	if err != nil {
		return false, err
	}
	return VerifyHex(pub, raw, strings.TrimSpace(string(sigRaw)))
}

// LoadSigned loads a policy, verifying its sidecar signature first when a
// public key is supplied. When pub is nil the policy is loaded unsigned —
// callers that require signatures must pass a key.
func LoadSigned(path string, pub ed25519.PublicKey) (*Policy, error) {
	if pub != nil {
		ok, err := VerifyPolicyFile(pub, path)
		if err != nil {
			return nil, fmt.Errorf("policy signature: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("policy signature verification failed")
		}
	}
	return LoadFile(path)
}
