package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Target struct {
	IP       string
	Hostname string
	Ports    []int
	Services []string
	OS       string
}

type Scanner struct {
	mu      sync.Mutex
	running bool
	results chan Target
	done    chan struct{}
}

func NewScanner() *Scanner {
	return &Scanner{
		results: make(chan Target, 1024),
		done:    make(chan struct{}),
	}
}

func (s *Scanner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	go s.scanLoop()
}

func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	close(s.done)
}

func (s *Scanner) Results() <-chan Target { return s.results }

func (s *Scanner) GetTargets() []Target {
	var targets []Target
	for {
		select {
		case t := <-s.results:
			targets = append(targets, t)
		default:
			return targets
		}
	}
}

func (s *Scanner) scanLoop() {
	for {
		select {
		case <-s.done:
			return
		default:
		}
		s.sweepSubnets()
		s.scanWiFi()
		time.Sleep(5 * time.Minute)
	}
}

func (s *Scanner) sweepSubnets() {
	localIPs := getLocalIPs()
	for _, ip := range localIPs {
		cidr := cidrFromIP(ip)
		if cidr == "" {
			continue
		}
		hosts := enumerateHosts(cidr)
		var wg sync.WaitGroup
		sem := make(chan struct{}, 20)
		for _, host := range hosts {
			wg.Add(1)
			sem <- struct{}{}
			go func(h string) {
				defer wg.Done()
				defer func() { <-sem }()
				ports := scanCommonPorts(h)
				if len(ports) > 0 {
					s.emitTarget(h, ports)
				}
			}(host)
		}
		wg.Wait()
	}
}

func (s *Scanner) emitTarget(ip string, ports []int) {
	t := Target{
		IP:       ip,
		Ports:    ports,
		Services: resolveServices(ports),
		Hostname: resolveHostname(ip),
	}
	select {
	case s.results <- t:
	default:
	}
}

func (s *Scanner) scanWiFi() {
	aps := scanWiFiAPs()
	for _, ap := range aps {
		s.emitTarget(ap.BSSID, nil)
	}
}

func getLocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
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

func cidrFromIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

func enumerateHosts(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var hosts []string
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	for ; ipnet.Contains(ip); incIP(ip) {
		if ip[3] == 0 || ip[3] == 255 {
			continue
		}
		hosts = append(hosts, ip.String())
		if len(hosts) >= 254 {
			break
		}
	}
	return hosts
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanCommonPorts(host string) []int {
	ports := []int{22, 80, 443, 445, 8080, 3306, 6379, 27017, 21, 23, 3389, 8443, 9090, 3000, 5000, 9200}
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return open
}

func resolveServices(ports []int) []string {
	svc := make([]string, 0, len(ports))
	for _, p := range ports {
		switch p {
		case 22:
			svc = append(svc, "ssh")
		case 80:
			svc = append(svc, "http")
		case 443:
			svc = append(svc, "https")
		case 445:
			svc = append(svc, "smb")
		case 3306:
			svc = append(svc, "mysql")
		case 6379:
			svc = append(svc, "redis")
		case 27017:
			svc = append(svc, "mongodb")
		case 8080:
			svc = append(svc, "http-proxy")
		case 21:
			svc = append(svc, "ftp")
		case 3389:
			svc = append(svc, "rdp")
		default:
			svc = append(svc, fmt.Sprintf("tcp/%d", p))
		}
	}
	return svc
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimSuffix(names[0], ".")
}

type APInfo struct {
	SSID   string
	BSSID  string
	Signal int
	Enc    string
}

func scanWiFiAPs() []APInfo {
	// Simple passive scan by checking iw output
	if aps := iwScan(); len(aps) > 0 {
		return aps
	}
	return nmcliScan()
}

func iwScan() []APInfo {
	return nil
}

func nmcliScan() []APInfo {
	return nil
}
