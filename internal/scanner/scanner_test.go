package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestCIDRFromIP(t *testing.T) {
	cases := map[string]string{
		"192.168.1.77": "192.168.1.0/24",
		"10.0.0.5":     "10.0.0.0/24",
		"172.16.8.200": "172.16.8.0/24",
		"not-an-ip":    "",
		"1.2.3.4.5":    "",
	}
	for in, want := range cases {
		if got := cidrFromIP(in); got != want {
			t.Errorf("cidrFromIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnumerateHosts(t *testing.T) {
	hosts := enumerateHosts("192.168.50.0/30")
	// /30 => network 192.168.50.0, broadcast .3; usable .1 and .2 only.
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts in /30, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "192.168.50.1" || hosts[1] != "192.168.50.2" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
	if enumerateHosts("bad/cidr") != nil {
		t.Fatal("bad cidr should return nil")
	}
}

func TestIncIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.255").To4()
	incIP(ip)
	if ip.String() != "10.0.1.0" {
		t.Fatalf("incIP carry failed: %s", ip)
	}
}

func TestScanCommonPortsLocalhost(t *testing.T) {
	// Bind a listener on one of the scanned ports and confirm the scanner
	// finds it.  Skip when the port cannot be bound (CI contention).
	ln, err := net.Listen("tcp", "127.0.0.1:3000")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:3000: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ports := scanCommonPorts("127.0.0.1")
	found := false
	for _, p := range ports {
		if p == 3000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("scanner did not find open port 3000; got %v", ports)
	}
	ln.Close()
	<-done
}

func TestResolveServices(t *testing.T) {
	svc := resolveServices([]int{22, 80, 9999})
	joined := strings.Join(svc, ",")
	if !strings.Contains(joined, "ssh") || !strings.Contains(joined, "http") {
		t.Fatalf("resolveServices missing entries: %v", svc)
	}
}

func TestScannerLifecycle(t *testing.T) {
	s := NewScanner()
	s.Start()
	s.Start() // idempotent
	// give the loop a moment, then stop cleanly (no panic/race)
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}
