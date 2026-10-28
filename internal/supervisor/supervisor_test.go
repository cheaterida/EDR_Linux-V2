package supervisor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edr/internal/liveness"
	"edr/internal/requestauth"
)

func TestQuorumIssuesRestartIntentWithCooldown(t *testing.T) {
	secret := []byte("s3cr3t-secret")
	srv := NewServer(Options{Secret: secret, DecisionTTL: time.Minute, HostStaleAfter: 5 * time.Second})
	h := srv.Handler()

	post := func(req HeartbeatRequest) HeartbeatResponse {
		body, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPost, "/v0/supervisor/heartbeat", bytes.NewReader(body))
		auth := requestauth.New(secret, time.Minute)
		auth.Sign(r, body, req.RequestID, time.Now().UTC())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var out HeartbeatResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	hb := liveness.Heartbeat{InstanceID: "edr-a", Unix: time.Now().Unix()}
	first := post(HeartbeatRequest{RequestID: "r1", SentAt: time.Now().UTC(), InstanceID: "edr-a", PeerInstanceID: "edr-b", PeerState: "down", Local: hb})
	if first.RestartIntent == nil || first.RestartIntent.Target != "edr-b" {
		t.Fatalf("expected restart intent for edr-b, got %+v", first)
	}
	second := post(HeartbeatRequest{RequestID: "r2", SentAt: time.Now().UTC(), InstanceID: "edr-a", PeerInstanceID: "edr-b", PeerState: "down", Local: hb})
	if second.RestartIntent != nil {
		t.Fatalf("cooldown should suppress a second intent, got %+v", second)
	}
}

func TestUnauthorizedHeartbeatRejected(t *testing.T) {
	srv := NewServer(Options{Secret: []byte("secret")})
	body := []byte(`{"instance_id":"x"}`)
	r := httptest.NewRequest(http.MethodPost, "/v0/supervisor/heartbeat", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without signature, got %d", w.Code)
	}
}
