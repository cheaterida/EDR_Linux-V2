package center

import (
	"testing"
	"time"

	"edr/internal/event"
)

func ev(seq uint64, prev, hash string) event.Event {
	return event.Event{
		Host:  "h1",
		Time:  time.Now().UTC(),
		Chain: &event.ChainMeta{Version: "v2.0", ChainID: "c", Seq: seq, PrevHash: prev, Hash: hash},
	}
}

func TestIngestDedupAndContinuity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Ingest(ev(1, "", "h1")) {
		t.Fatal("seq1 not stored")
	}
	if !s.Ingest(ev(2, "h1", "h2")) {
		t.Fatal("seq2 not stored")
	}
	if s.Ingest(ev(2, "h1", "h2")) {
		t.Fatal("duplicate seq2 stored")
	}
	if !s.Ingest(ev(5, "h2", "h5")) {
		t.Fatal("seq5 not stored")
	}
	hosts := s.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts=%d", len(hosts))
	}
	if hosts[0].Events != 3 {
		t.Fatalf("events=%d, want 3", hosts[0].Events)
	}
	if hosts[0].Gaps != 1 {
		t.Fatalf("gaps=%d, want 1", hosts[0].Gaps)
	}

	out, err := s.Query(Filter{Host: "h1", Limit: 10})
	if err != nil || len(out) != 3 {
		t.Fatalf("query=%d err=%v", len(out), err)
	}
}
