package adminauth

import (
	"testing"
	"time"
)

func TestIssueVerifyAndReplay(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := New(key)
	now := time.Now()
	tok, _, err := a.Issue("policy-reload", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(tok, "policy-reload", now); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := a.Verify(tok, "policy-reload", now); err != ErrReplayed {
		t.Fatalf("replay not rejected: %v", err)
	}
}

func TestWrongActionRejected(t *testing.T) {
	key, _ := GenerateKey()
	a := New(key)
	tok, _, _ := a.Issue("shutdown", time.Now())
	if err := a.Verify(tok, "policy-reload", time.Now()); err == nil {
		t.Fatal("token for another action accepted")
	}
}

func TestExpiredRejected(t *testing.T) {
	key, _ := GenerateKey()
	a := New(key)
	tok, _, _ := a.Issue("shutdown", time.Now())
	if err := a.Verify(tok, "shutdown", time.Now().Add(2*time.Hour)); err != ErrExpired {
		t.Fatalf("expired token not rejected: %v", err)
	}
}

func TestDisabledWithoutKey(t *testing.T) {
	a := New(nil)
	if a.Enabled() {
		t.Fatal("auth should be disabled without a key")
	}
	if _, _, err := a.Issue("shutdown", time.Now()); err == nil {
		t.Fatal("issue should fail without key")
	}
}
