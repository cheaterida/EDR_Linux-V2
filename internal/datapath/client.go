package datapath

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"edr/internal/event"
)

const maxFrame = 16 << 20

// ActionResult is the daemon's reply to an action request.
type ActionResult struct {
	ID       string
	Success  bool
	Enforced bool
	Detail   string
}

// Client is a connection to the datapath daemon. Safe for concurrent Send.
type Client struct {
	conn    net.Conn
	mu      sync.Mutex
	pending map[string]chan ActionResult
	events  chan event.Event
	closed  chan struct{}
	once    sync.Once
}

// Dial connects to the daemon's Unix socket and starts the read loop.
func Dial(socket string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:    conn,
		pending: map[string]chan ActionResult{},
		events:  make(chan event.Event, 256),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Events returns the file-access decision stream.
func (c *Client) Events() <-chan event.Event { return c.events }

func EncodeFrame(m Message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Cap the body so a runaway message cannot exceed what the daemon accepts.
	if len(body)+1 > maxFrame {
		return nil, fmt.Errorf("datapath: message too large")
	}
	buf := make([]byte, 5+len(body))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(1+len(body)))
	buf[4] = FrameVersion
	copy(buf[5:], body)
	return buf, nil
}

func DecodeFrame(body []byte) (Message, error) {
	var m Message
	if len(body) == 0 {
		return m, fmt.Errorf("datapath: empty frame")
	}
	if body[0] != FrameVersion {
		return m, fmt.Errorf("datapath: unsupported frame version %d", body[0])
	}
	if err := json.Unmarshal(body[1:], &m); err != nil {
		return m, err
	}
	return m, nil
}

func (c *Client) send(m Message) error {
	frame, err := EncodeFrame(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.conn.Write(frame)
	return err
}

// Hello introduces the agent to the daemon.
func (c *Client) Hello(agentPID uint32) error {
	return c.send(Message{Type: "hello", AgentPID: agentPID})
}

// PushPolicy replaces the daemon's decision table.
func (c *Client) PushPolicy(version uint64, rules []FileRule) error {
	return c.send(Message{Type: "policy", Version: version, Rules: rules})
}

// Kill asks the daemon to kill pid via pidfd (PID-reuse safe).
func (c *Client) Kill(pid int32, exe string, startTicks uint64) (ActionResult, error) {
	id := fmt.Sprintf("kill-%d-%d", pid, time.Now().UnixNano())
	ch := make(chan ActionResult, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.send(Message{Type: "action", ID: id, Action: "kill", PID: pid, Exe: exe, StartTicks: startTicks}); err != nil {
		return ActionResult{}, err
	}
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(3 * time.Second):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ActionResult{}, fmt.Errorf("datapath: action timeout")
	case <-c.closed:
		return ActionResult{}, fmt.Errorf("datapath: closed")
	}
}

func (c *Client) readLoop() {
	defer close(c.events)
	r := bufio.NewReader(c.conn)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(hdr[:])
		if n == 0 || n > maxFrame {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		m, err := DecodeFrame(body)
		if err != nil {
			continue
		}
		c.dispatch(m)
	}
}

func (c *Client) dispatch(m Message) {
	switch m.Type {
	case "event":
		ev := event.Event{
			Kind: event.KindFileOp,
			PID:  uint32(m.PID),
			Comm: m.Comm,
			File: &event.FileInfo{Path: m.Path, Op: m.Op},
			Detail: map[string]any{
				"source":   "datapath",
				"decision": m.Decision,
				"rule_id":  m.RuleID,
			},
		}
		ev.Normalize()
		select {
		case c.events <- ev:
		default:
		}
	case "action_result":
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- ActionResult{ID: m.ID, Success: m.Success, Enforced: m.Enforced, Detail: m.Detail}
		}
	}
}

// Close shuts the connection down.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.conn.Close()
	})
	return err
}
