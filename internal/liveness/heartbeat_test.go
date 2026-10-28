package liveness

import (
	"testing"
	"time"
)

func TestStateTransitions(t *testing.T) {
	now := time.Now()
	hb := Heartbeat{InstanceID: "a", Unix: now.Unix()}
	if s := State(now, hb, 3, 5, time.Second); s != "healthy" {
		t.Fatalf("healthy: %s", s)
	}
	if s := State(now.Add(4*time.Second), hb, 3, 5, time.Second); s != "suspect" {
		t.Fatalf("suspect: %s", s)
	}
	if s := State(now.Add(6*time.Second), hb, 3, 5, time.Second); s != "down" {
		t.Fatalf("down: %s", s)
	}
	if s := State(now, Heartbeat{}, 3, 5, time.Second); s != "starting" {
		t.Fatalf("starting: %s", s)
	}
}

func TestWriteRead(t *testing.T) {
	dir := t.TempDir()
	hb := Heartbeat{InstanceID: "edr-a", Unix: time.Now().Unix(), RestartGeneration: 7}
	if err := Write(dir, hb); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir, "edr-a")
	if err != nil || got.RestartGeneration != 7 {
		t.Fatalf("read: %+v err=%v", got, err)
	}
}
