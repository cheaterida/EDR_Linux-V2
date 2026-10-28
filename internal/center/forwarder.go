package center

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"edr/internal/event"
	"edr/internal/requestauth"
)

// Forwarder mirrors sealed event lines to the center. It implements
// io.Writer so it can be composed with the local file sink, batches in the
// background, and never blocks the pipeline (drops are counted).
type Forwarder struct {
	url     string
	auth    *requestauth.Authenticator
	ch      chan event.Event
	dropped atomic.Uint64
	client  *http.Client
}

// NewForwarder builds a forwarder with a bounded queue.
func NewForwarder(url string, secret []byte, queue int) *Forwarder {
	if queue <= 0 {
		queue = 2048
	}
	return &Forwarder{
		url:    url,
		auth:   requestauth.New(secret, 60*time.Second),
		ch:     make(chan event.Event, queue),
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Write parses a sealed JSONL line and enqueues it for forwarding.
func (f *Forwarder) Write(p []byte) (int, error) {
	var ev event.Event
	if err := json.Unmarshal(p, &ev); err == nil {
		select {
		case f.ch <- ev:
		default:
			f.dropped.Add(1)
		}
	}
	return len(p), nil
}

// Start launches the batching loop.
func (f *Forwarder) Start(ctx context.Context) { go f.loop(ctx) }

func (f *Forwarder) loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	batch := make([]event.Event, 0, 128)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		f.send(batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-t.C:
			flush()
		case ev := <-f.ch:
			batch = append(batch, ev)
			if len(batch) >= 128 {
				flush()
			}
		}
	}
}

func (f *Forwarder) send(batch []event.Event) {
	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		f.dropped.Add(uint64(len(batch)))
		return
	}
	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		f.dropped.Add(uint64(len(batch)))
		return
	}
	f.auth.Sign(req, body, "", time.Now().UTC())
	resp, err := f.client.Do(req)
	if err != nil {
		f.dropped.Add(uint64(len(batch)))
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		f.dropped.Add(uint64(len(batch)))
	}
}

// Dropped returns the number of events that could not be forwarded.
func (f *Forwarder) Dropped() uint64 { return f.dropped.Load() }

// MultiWriter fans out writes to every writer.
type MultiWriter []io.Writer

func (m MultiWriter) Write(p []byte) (int, error) {
	for _, w := range m {
		if _, err := w.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
