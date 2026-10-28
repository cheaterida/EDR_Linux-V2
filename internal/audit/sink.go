package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileSink appends sealed chain lines to a file with size-based rotation.
// It implements io.Writer so the pipeline audit stage can target it directly.
type FileSink struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
}

// NewFileSink creates a sink. maxBytes <= 0 disables rotation.
func NewFileSink(path string, maxBytes int64, maxBackups int) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return &FileSink{path: path, maxBytes: maxBytes, maxBackups: maxBackups}, nil
}

// Write appends a line, rotating first if needed.
func (s *FileSink) Write(line []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rotateIfNeeded(int64(len(line))); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(line)
}

// Close is a no-op (files are opened per write).
func (s *FileSink) Close() error { return nil }

func (s *FileSink) rotateIfNeeded(incoming int64) error {
	if s.maxBytes <= 0 {
		return nil
	}
	st, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size()+incoming <= s.maxBytes {
		return nil
	}
	if s.maxBackups <= 0 {
		s.maxBackups = 1
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", s.path, s.maxBackups))
	for i := s.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.path, i)
		dst := fmt.Sprintf("%s.%d", s.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	return os.Rename(s.path, s.path+".1")
}
