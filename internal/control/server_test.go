package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edr/internal/adminauth"
)

func withCred(r *http.Request, uid uint32, pid int32) *http.Request {
	ctx := context.WithValue(r.Context(), credKey{}, peerCred{uid: uid, pid: pid})
	return r.WithContext(ctx)
}

func TestAuthorizedUIDAllowList(t *testing.T) {
	s := New(Deps{AllowedUIDs: []int{0}})
	if !s.authorized(httptest.NewRecorder(), withCred(httptest.NewRequest("GET", "/v0/status", nil), 0, 10)) {
		t.Fatal("uid 0 should be authorized")
	}
	w := httptest.NewRecorder()
	if s.authorized(w, withCred(httptest.NewRequest("GET", "/v0/status", nil), 1000, 10)) {
		t.Fatal("uid 1000 should be rejected")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireAdminToken(t *testing.T) {
	key, err := adminauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ad := adminauth.New(key)
	s := New(Deps{AllowedUIDs: []int{0}, Admin: ad})

	tok, _, err := ad.Issue("policy-reload", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := withCred(httptest.NewRequest("POST", "/v0/policy/reload", nil), 1000, 10)
	r.Header.Set("X-EDR-Admin-Token", tok)
	if !s.requireAdmin(httptest.NewRecorder(), r, "policy-reload") {
		t.Fatal("valid admin token rejected")
	}

	r2 := withCred(httptest.NewRequest("POST", "/v0/policy/reload", nil), 1000, 10)
	if s.requireAdmin(httptest.NewRecorder(), r2, "policy-reload") {
		t.Fatal("missing token from non-root uid must be rejected")
	}
}

func TestHandlerRejectsWithoutPeerCreds(t *testing.T) {
	h := New(Deps{AllowedUIDs: []int{0}}).Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v0/status", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without peer credentials, got %d", w.Code)
	}
}
