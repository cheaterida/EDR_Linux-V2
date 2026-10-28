package lease

import (
	"testing"
	"time"
)

func TestAcquirePreventsSplitBrain(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	l1, err := Acquire(dir, "peer", "A", 10*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "peer", "B", 10*time.Second, now); err != ErrHeld {
		t.Fatalf("expected ErrHeld, got %v", err)
	}
	// Same holder may refresh.
	if _, err := Acquire(dir, "peer", "A", 10*time.Second, now.Add(time.Second)); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	// After expiry a different holder may take it.
	l3, err := Acquire(dir, "peer", "B", 10*time.Second, now.Add(11*time.Second))
	if err != nil {
		t.Fatalf("post-expiry acquire failed: %v", err)
	}
	if l3.LeaseID == l1.LeaseID {
		t.Fatal("new holder should get a fresh lease id")
	}
	// Release by id.
	if err := Release(dir, "peer", l3.LeaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "peer", "A", 10*time.Second, now.Add(12*time.Second)); err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}
}

func TestReleaseWrongID(t *testing.T) {
	dir := t.TempDir()
	if _, err := Acquire(dir, "peer", "A", 10*time.Second, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Release(dir, "peer", "bogus"); err != ErrHeld {
		t.Fatalf("expected ErrHeld for wrong id, got %v", err)
	}
}
