package center

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"edr/internal/requestauth"
)

// ExecFunc runs an orchestrated action on the agent and returns its outcome.
type ExecFunc func(ActionRequest) (success, enforced bool, detail string)

// ActionPoller pulls approved actions from the center and reports results.
type ActionPoller struct {
	base   string
	host   string
	auth   *requestauth.Authenticator
	client *http.Client
	exec   ExecFunc
}

// NewActionPoller builds a poller. base is the center root URL (e.g.
// http://center:7080); host is this agent's host label.
func NewActionPoller(base, host string, secret []byte, exec ExecFunc) *ActionPoller {
	return &ActionPoller{
		base:   strings.TrimRight(base, "/"),
		host:   host,
		auth:   requestauth.New(secret, 60*time.Second),
		client: &http.Client{Timeout: 5 * time.Second},
		exec:   exec,
	}
}

// Start polls until ctx is done.
func (p *ActionPoller) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.poll()
			}
		}
	}()
}

func (p *ActionPoller) poll() {
	req, err := http.NewRequest(http.MethodGet, p.base+"/v0/center/agent/actions?host="+url.QueryEscape(p.host), nil)
	if err != nil {
		return
	}
	p.auth.Sign(req, nil, "", time.Now().UTC())
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	if err := p.auth.VerifyBody(body, resp.Header.Get(requestauth.HeaderResponseSignature)); err != nil {
		return // tampered/missing signature: never act on unauthenticated actions
	}
	var actions []ActionRequest
	if err := json.Unmarshal(body, &actions); err != nil {
		return
	}
	for _, a := range actions {
		success, enforced, detail := p.exec(a)
		p.report(a.ID, success, enforced, detail)
	}
}

func (p *ActionPoller) report(id string, success, enforced bool, detail string) {
	payload, _ := json.Marshal(map[string]any{
		"id": id, "success": success, "enforced": enforced, "detail": detail,
	})
	req, err := http.NewRequest(http.MethodPost, p.base+"/v0/center/agent/actions/result", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	p.auth.Sign(req, payload, "", time.Now().UTC())
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
