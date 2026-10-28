package collect

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"edr/internal/event"
)

// Inotify is a fallback file-change observer used when fanotify is not
// available or synchronous deny is not required. It is purely observational
// (create/write/delete) and never blocks the target process.
type Inotify struct {
	fd      int
	mu      sync.Mutex
	wd      map[int]string
	out     chan event.Event
	dropped atomic.Uint64
	done    chan struct{}
	once    sync.Once
}

// NewInotify creates a watcher and recursively watches every path.
func NewInotify(paths []string) (*Inotify, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	w := &Inotify{
		fd:   fd,
		wd:   map[int]string{},
		out:  make(chan event.Event, 512),
		done: make(chan struct{}),
	}
	for _, p := range paths {
		_ = w.addRecursive(p)
	}
	return w, nil
}

// Events returns the file-change stream.
func (w *Inotify) Events() <-chan event.Event { return w.out }

// Dropped returns how many events were dropped because the consumer lagged.
func (w *Inotify) Dropped() uint64 { return w.dropped.Load() }

const inotifyMask = unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE |
	unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE

func (w *Inotify) addRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.IsDir() {
			return nil
		}
		wd, err := unix.InotifyAddWatch(w.fd, path, inotifyMask)
		if err == nil {
			w.mu.Lock()
			w.wd[wd] = path
			w.mu.Unlock()
		}
		return nil
	})
}

func (w *Inotify) base(wd int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.wd[wd]
}

// Start begins the read loop until ctx is cancelled or Close is called.
func (w *Inotify) Start(ctx context.Context) {
	go func() {
		defer close(w.done)
		defer close(w.out)
		buf := make([]byte, 64<<10)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 500)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return
			}
			if n <= 0 {
				continue
			}
			nr, err := unix.Read(w.fd, buf)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EINTR {
					continue
				}
				return
			}
			if nr <= 0 {
				continue
			}
			w.parse(buf[:nr])
		}
	}()
}

func (w *Inotify) parse(buf []byte) {
	offset := 0
	for offset+unix.SizeofInotifyEvent <= len(buf) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		nameStart := offset + unix.SizeofInotifyEvent
		nameEnd := nameStart + nameLen
		if nameEnd > len(buf) {
			break
		}
		name := string(bytes.TrimRight(buf[nameStart:nameEnd], "\x00"))
		base := w.base(int(raw.Wd))
		path := base
		if name != "" {
			path = filepath.Join(base, name)
		}
		if raw.Mask&unix.IN_ISDIR != 0 && (raw.Mask&unix.IN_CREATE != 0 || raw.Mask&unix.IN_MOVED_TO != 0) {
			_ = w.addRecursive(path)
		}
		op := ""
		switch {
		case raw.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
			op = "create"
		case raw.Mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE) != 0:
			op = "write"
		case raw.Mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
			op = "delete"
		}
		if op != "" && path != "" {
			ev := event.Event{
				Kind:   event.KindFileOp,
				File:   &event.FileInfo{Path: path, Op: op},
				Detail: map[string]any{"source": "inotify"},
			}
			ev.Normalize()
			select {
			case w.out <- ev:
			default:
				w.dropped.Add(1)
			}
		}
		offset += unix.SizeofInotifyEvent + nameLen
	}
}

// Close releases the inotify descriptor.
func (w *Inotify) Close() error {
	var err error
	w.once.Do(func() { err = unix.Close(w.fd) })
	return err
}
