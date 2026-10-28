package requestauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	a := New([]byte("shared-secret"), 30*time.Second)
	body := []byte(`{"hello":"world"}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/supervisor/heartbeat", strings.NewReader(string(body)))
	a.Sign(req, body, "req-1", time.Now().UTC())
	if err := a.Authorize(req, body); err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if err := a.Authorize(req, body); err == nil {
		t.Fatal("replay should be rejected")
	}
}

func TestWrongSecret(t *testing.T) {
	signer := New([]byte("secret-A"), 30*time.Second)
	verifier := New([]byte("secret-B"), 30*time.Second)
	body := []byte("{}")
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
	signer.Sign(req, body, "r", time.Now().UTC())
	if err := verifier.Authorize(req, body); err == nil {
		t.Fatal("wrong secret must fail")
	}
}

func TestDisabledWithoutSecret(t *testing.T) {
	a := New(nil, 0)
	if a.Enabled() {
		t.Fatal("should be disabled")
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if err := a.Authorize(req, nil); err != nil {
		t.Fatalf("disabled auth should allow: %v", err)
	}
}
