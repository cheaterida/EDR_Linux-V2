// Package notify delivers EDR events to external channels: HTTP webhooks
// (generic/dingtalk/wechat_work/feishu), remote syslog (RFC 5424) and email.
// Delivery is asynchronous with a bounded queue; drops are counted, never
// silently lost.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"edr/internal/event"
)

// WebhookConfig configures one webhook endpoint.
type WebhookConfig struct {
	URL         string            `json:"url"`
	Format      string            `json:"format,omitempty"` // generic|dingtalk|wechat_work|feishu
	MinSeverity string            `json:"min_severity,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	TimeoutSec  int               `json:"timeout_sec,omitempty"`
}

// SyslogConfig configures a remote syslog target (RFC 5424).
type SyslogConfig struct {
	Enabled     bool   `json:"enabled"`
	Network     string `json:"network,omitempty"` // udp|tcp
	Address     string `json:"address,omitempty"` // host:port
	Facility    int    `json:"facility,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
}

// EmailConfig configures SMTP alerts.
type EmailConfig struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host,omitempty"`
	Port        int      `json:"port,omitempty"`
	Username    string   `json:"username,omitempty"`
	Password    string   `json:"password,omitempty"` // supports $ENV_NAME
	From        string   `json:"from,omitempty"`
	To          []string `json:"to,omitempty"`
	UseTLS      bool     `json:"use_tls,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
}

// Config is the whole notification document.
type Config struct {
	Webhooks  []WebhookConfig `json:"webhooks,omitempty"`
	Syslog    SyslogConfig    `json:"syslog,omitempty"`
	Email     EmailConfig     `json:"email,omitempty"`
	QueueSize int             `json:"queue_size,omitempty"`
}

// Load reads a notification config file.
func Load(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	return c, nil
}

// Dispatcher fans events out to every configured channel.
type Dispatcher struct {
	webhooks []WebhookConfig
	syslog   SyslogConfig
	email    EmailConfig
	client   *http.Client
	ch       chan *event.Event
	dropped  atomic.Uint64
	sent     atomic.Uint64
}

// New builds a dispatcher from config.
func New(cfg Config) *Dispatcher {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	return &Dispatcher{
		webhooks: cfg.Webhooks,
		syslog:   cfg.Syslog,
		email:    cfg.Email,
		client:   &http.Client{Timeout: 5 * time.Second},
		ch:       make(chan *event.Event, cfg.QueueSize),
	}
}

// Enabled reports whether any channel is configured.
func (d *Dispatcher) Enabled() bool {
	return len(d.webhooks) > 0 || d.syslog.Enabled || d.email.Enabled
}

// Start runs the delivery loop until ctx is done.
func (d *Dispatcher) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-d.ch:
				d.deliver(ev)
			}
		}
	}()
}

// Notify enqueues an event (non-blocking; drops are counted).
func (d *Dispatcher) Notify(ev *event.Event) {
	if d == nil || ev == nil || !d.Enabled() {
		return
	}
	select {
	case d.ch <- ev:
	default:
		d.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped due to a full queue.
func (d *Dispatcher) Dropped() uint64 { return d.dropped.Load() }

// Sent returns the number of events delivered to at least one channel.
func (d *Dispatcher) Sent() uint64 { return d.sent.Load() }

func (d *Dispatcher) deliver(ev *event.Event) {
	sev := ev.Severity()
	msg := format(ev)
	delivered := false
	for _, wh := range d.webhooks {
		if rank(sev) < rank(wh.MinSeverity) {
			continue
		}
		if err := d.postWebhook(wh, ev, msg); err == nil {
			delivered = true
		}
	}
	if d.syslog.Enabled && rank(sev) >= rank(d.syslog.MinSeverity) {
		if err := d.sendSyslog(ev, msg); err == nil {
			delivered = true
		}
	}
	if d.email.Enabled && rank(sev) >= rank(d.email.MinSeverity) {
		if err := d.sendEmail(ev, msg); err == nil {
			delivered = true
		}
	}
	if delivered {
		d.sent.Add(1)
	}
}

// ---- formatting ----

func format(ev *event.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[EDR][%s] %s rule=%s", ev.Severity(), ev.Kind.String(), ev.ChainRule())
	fmt.Fprintf(&b, " host=%s", ev.Host)
	if ev.Comm != "" {
		fmt.Fprintf(&b, " comm=%s pid=%d", ev.Comm, ev.PID)
	}
	if ev.File != nil && ev.File.Path != "" {
		fmt.Fprintf(&b, " file=%s op=%s", ev.File.Path, ev.File.Op)
	}
	if ev.Net != nil && ev.Net.RemoteAddr != "" {
		fmt.Fprintf(&b, " dst=%s:%d", ev.Net.RemoteAddr, ev.Net.RemotePort)
	}
	return b.String()
}

func rank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ---- webhook ----

func (d *Dispatcher) postWebhook(wh WebhookConfig, ev *event.Event, msg string) error {
	var body []byte
	switch strings.ToLower(wh.Format) {
	case "dingtalk", "wechat_work":
		body, _ = json.Marshal(map[string]any{"msgtype": "text", "text": map[string]any{"content": msg}})
	case "feishu":
		body, _ = json.Marshal(map[string]any{"msg_type": "text", "content": map[string]any{"text": msg}})
	default:
		body, _ = json.Marshal(map[string]any{
			"host": ev.Host, "severity": ev.Severity(), "kind": ev.Kind.String(),
			"rule_id": ev.ChainRule(), "comm": ev.Comm, "pid": ev.PID, "message": msg,
		})
	}
	req, err := http.NewRequest(http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}
	client := d.client
	if wh.TimeoutSec > 0 {
		client = &http.Client{Timeout: time.Duration(wh.TimeoutSec) * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---- syslog (RFC 5424) ----

func (d *Dispatcher) sendSyslog(ev *event.Event, msg string) error {
	network := d.syslog.Network
	if network != "tcp" {
		network = "udp"
	}
	facility := d.syslog.Facility
	if facility <= 0 {
		facility = 3 // LOG_DAEMON
	}
	pri := facility<<3 | syslogSev(ev.Severity())
	host := ev.Host
	if host == "" {
		host = "-"
	}
	line := fmt.Sprintf("<%d>1 %s %s edr-agent %d - - %s\n",
		pri, ev.Time.UTC().Format(time.RFC3339), host, ev.PID, msg)
	conn, err := net.DialTimeout(network, d.syslog.Address, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(line))
	return err
}

func syslogSev(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	default:
		return 6 // info
	}
}

// ---- email ----

func (d *Dispatcher) sendEmail(ev *event.Event, msg string) error {
	e := d.email
	if e.Host == "" || len(e.To) == 0 {
		return fmt.Errorf("email not configured")
	}
	pass := e.Password
	if strings.HasPrefix(pass, "$") {
		pass = os.Getenv(strings.TrimPrefix(pass, "$"))
	}
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)
	auth := smtp.PlainAuth("", e.Username, pass, e.Host)
	subject := fmt.Sprintf("[EDR][%s] %s on %s", ev.Severity(), ev.ChainRule(), ev.Host)
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		e.From, strings.Join(e.To, ","), subject, msg)
	if e.UseTLS {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: e.Host})
		if err != nil {
			return err
		}
		c, err := smtp.NewClient(conn, e.Host)
		if err != nil {
			return err
		}
		defer c.Close()
		if e.Username != "" {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
		if err := c.Mail(e.From); err != nil {
			return err
		}
		for _, to := range e.To {
			if err := c.Rcpt(to); err != nil {
				return err
			}
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		_, _ = w.Write([]byte(body))
		return w.Close()
	}
	return smtp.SendMail(addr, auth, e.From, e.To, []byte(body))
}
