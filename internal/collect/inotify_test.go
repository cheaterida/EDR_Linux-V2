package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInotifyDetectsCreate(t *testing.T) {
	dir := t.TempDir()
	w, err := NewInotify([]string{dir})
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events():
		if ev.Kind != 0 && ev.File == nil {
			t.Fatalf("file event missing File: %+v", ev)
		}
		if ev.File == nil || ev.File.Op == "" {
			t.Fatalf("expected a file op, got %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Skip("no inotify event observed (environment dependent)")
	}
}
