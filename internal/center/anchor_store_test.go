package center

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edr/internal/requestauth"
)

func TestAnchorStore(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAnchor("h1", anchorRecord{ChainID: "c1", Seq: 5, Hash: "abc", PushedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	rec, ok := s.LoadAnchor("h1")
	if !ok || rec.ChainID != "c1" || rec.Seq != 5 {
		t.Fatalf("load: %+v ok=%v", rec, ok)
	}
}

func TestAnchorEndpointNeverLowers(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := OpenActions(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("center-secret")
	srv := NewServer(store, key).WithActions(actions)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	auth := requestauth.New(key, 60*time.Second)

	post := func(seq uint64) *http.Response {
		body, _ := json.Marshal(anchorRecord{ChainID: "c1", Seq: seq, Hash: "h", PushedAt: time.Now().UTC()})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v0/center/anchor?host=h1", bytes.NewReader(body))
		auth.Sign(req, body, "", time.Now().UTC())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := post(10); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("push seq10: %d", resp.StatusCode)
	}
	resp := post(3) // a lower anchor must be ignored
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if kept, _ := out["kept"].(bool); !kept {
		t.Fatalf("lower anchor was accepted: %v", out)
	}
	rec, ok := store.LoadAnchor("h1")
	if !ok || rec.Seq != 10 {
		t.Fatalf("anchor lowered: %+v", rec)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v0/center/anchor?host=h1", nil)
	auth.Sign(req, nil, "", time.Now().UTC())
	gresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	gb, _ := io.ReadAll(gresp.Body)
	if err := auth.VerifyBody(gb, gresp.Header.Get(requestauth.HeaderResponseSignature)); err != nil {
		t.Fatalf("anchor GET not signed: %v", err)
	}
}
