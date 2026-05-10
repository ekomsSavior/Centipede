package sensor

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type EnvInfo struct {
	Hostname    string
	OS          string
	Arch        string
	Kernel      string
	Uptime      int64
	CPUs        int
	MemTotal    int64
	PublicIP    string
	LocalIPs    []string
	Processes   int
	Container   bool
	VM          bool
	HasWiFi     bool
	HasSSH      bool
	HasDocker   bool
}

func Gather() *EnvInfo {
	info := &EnvInfo{
		Hostname:  getHostname(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Kernel:    readKernel(),
		Uptime:    readUptime(),
		CPUs:      runtime.NumCPU(),
		MemTotal:  readMemTotal(),
		LocalIPs:  getLocalIPs(),
		Container: detectContainer(),
		VM:        detectVM(),
		HasWiFi:   detectWiFi(),
		HasSSH:    detectSSH(),
		HasDocker: detectDocker(),
	}
	info.Processes = countProcesses()
	return info
}

func (e *EnvInfo) IsInteresting() bool {
	if e.HasDocker {
		return true
	}
	if e.HasWiFi {
		return true
	}
	if e.VM {
		return true
	}
	return false
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func readKernel() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func readUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var uptime float64
	fmt.Sscanf(string(data), "%f", &uptime)
	return int64(uptime)
}

func readMemTotal() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			var kb int64
			fmt.Sscanf(line, "MemTotal: %d kB", &kb)
			return kb * 1024
		}
	}
	return 0
}

func countProcesses() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			pid := 0
			if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil {
				n++
			}
		}
	}
	return n
}

func detectContainer() bool {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "kubepods") ||
		strings.Contains(content, "lxc") ||
		strings.Contains(content, "containerd")
}

func detectVM() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	content := string(data)
	if strings.Contains(content, "hypervisor") || strings.Contains(content, "QEMU") {
		return true
	}
	// Check DMI
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "virtual") {
			return true
		}
	}
	return false
}

func detectWiFi() bool {
	// Check for wireless interfaces
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		name := iface.Name()
		wireless := fmt.Sprintf("/sys/class/net/%s/wireless", name)
		if _, err := os.Stat(wireless); err == nil {
			return true
		}
		// Check type
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", name)); err == nil {
			if strings.TrimSpace(string(data)) == "802" {
				return true
			}
		}
	}
	return false
}

func detectSSH() bool {
	return isFile("/etc/ssh/sshd_config") || isFile("/usr/sbin/sshd")
}

func detectDocker() bool {
	return isFile("/var/run/docker.sock") || isFile("/usr/bin/docker")
}

func isFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getLocalIPs() []string {
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var ips []string
	for _, iface := range ifaces {
		addr, err := os.ReadFile(fmt.Sprintf(
			"/sys/class/net/%s/address", iface.Name()))
		if err == nil {
			ips = append(ips, strings.TrimSpace(string(addr)))
		}
	}
	return ips
}
