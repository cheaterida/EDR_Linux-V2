package requestauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestQueryIsSigned ensures a signed request cannot have its query string
// mutated (e.g. redirecting an action poll to another host).
func TestQueryIsSigned(t *testing.T) {
	a := New([]byte("secret"), 30*time.Second)
	req := httptest.NewRequest(http.MethodGet, "/v0/center/agent/actions?host=a", nil)
	a.Sign(req, nil, "r1", time.Now().UTC())
	if err := a.Authorize(req, nil); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	req.URL.RawQuery = "host=b"
	req.Header.Set(HeaderRequestID, "r2") // avoid the replay check masking the signature check
	if err := a.Authorize(req, nil); err == nil {
		t.Fatal("mutated query string accepted")
	}
}

// TestResponseBodySignature ensures response bodies are authenticated so an
// on-path attacker cannot inject a destructive action.
func TestResponseBodySignature(t *testing.T) {
	a := New([]byte("secret"), 30*time.Second)
	body := []byte(`[{"id":"x","action":"kill","pid":1}]`)
	sig := a.SignBody(body)
	if sig == "" {
		t.Fatal("no signature produced")
	}
	if err := a.VerifyBody(body, sig); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	tampered := []byte(`[{"id":"x","action":"kill","pid":2}]`)
	if err := a.VerifyBody(tampered, sig); err == nil {
		t.Fatal("tampered body accepted")
	}
	if err := a.VerifyBody(body, ""); err == nil {
		t.Fatal("missing signature accepted")
	}
}
