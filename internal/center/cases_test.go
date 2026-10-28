package center

import "testing"

func TestCaseLifecycleAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create("chain on h1", "high", []string{"h1"}, []string{"T1059-x"}, []string{"T1059 Command"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "new" {
		t.Fatalf("initial status = %q", c.Status)
	}
	if err := s.SetStatus(c.ID, "investigating"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisposition(c.ID, "true_positive", "confirmed beacon"); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(c.ID)
	if !ok {
		t.Fatal("case missing")
	}
	if got.Status != "investigating" || got.Disposition != "true_positive" {
		t.Fatalf("case state = %+v", got)
	}
	if len(got.Timeline) < 3 {
		t.Fatalf("timeline = %+v", got.Timeline)
	}

	// Reopen from disk.
	s2, err := OpenCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	got2, ok := s2.Get(c.ID)
	if !ok || got2.Status != "investigating" || got2.Disposition != "true_positive" {
		t.Fatalf("persisted case = %+v ok=%v", got2, ok)
	}
}

func TestCaseRejectsInvalidState(t *testing.T) {
	s, _ := OpenCases(t.TempDir())
	c, _ := s.Create("t", "low", nil, nil, nil)
	if err := s.SetStatus(c.ID, "bogus"); err == nil {
		t.Fatal("invalid status accepted")
	}
	if err := s.SetDisposition(c.ID, "bogus", ""); err == nil {
		t.Fatal("invalid disposition accepted")
	}
	if err := s.SetStatus("missing", "closed"); err == nil {
		t.Fatal("unknown case accepted")
	}
}
