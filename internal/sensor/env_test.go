package sensor

import (
	"os"
	"strings"
	"testing"
)

func TestGatherPopulates(t *testing.T) {
	env := Gather()
	if env == nil {
		t.Fatal("Gather returned nil")
	}
	if env.Hostname == "" {
		t.Error("hostname empty")
	}
	if env.OS == "" || env.Arch == "" {
		t.Error("os/arch empty")
	}
	if env.Kernel == "" {
		t.Error("kernel empty")
	}
	if env.CPUs < 1 {
		t.Errorf("CPUs = %d", env.CPUs)
	}
	if env.MemTotal <= 0 {
		t.Errorf("MemTotal = %d", env.MemTotal)
	}
	if len(env.LocalIPs) == 0 {
		t.Error("no local IPs detected")
	}
	if env.Processes <= 0 {
		t.Errorf("Processes = %d", env.Processes)
	}
	// Container should be true inside this test environment (docker/k8s).
	if !env.Container {
		t.Log("note: container detection returned false (may run on bare metal)")
	}
}

func TestDetectHelpers(t *testing.T) {
	if detectContainer() {
		t.Log("running in container")
	}
	if detectVM() {
		t.Log("VM markers present")
	}
	// Reads of /proc paths must never panic even when absent.
	_ = readKernel()
	_ = readUptime()
	_ = readMemTotal()
	_ = countProcesses()
	_ = getLocalIPs()
}

func TestIsInteresting(t *testing.T) {
	env := Gather()
	if env == nil {
		t.Fatal("Gather nil")
	}
	// Should not panic and should return bool consistent with flags.
	_ = env.IsInteresting()
}

func TestHostnameMatchesOS(t *testing.T) {
	h, err := os.Hostname()
	if err != nil {
		t.Skip("hostname unavailable")
	}
	if env := Gather(); env.Hostname != h {
		t.Errorf("Gather hostname %q != os.Hostname %q", env.Hostname, h)
	}
}

func TestKernelFormat(t *testing.T) {
	k := readKernel()
	if k == "" {
		t.Skip("kernel string empty (unlikely)")
	}
	if !strings.Contains(k, "Linux") && !strings.Contains(k, ".") {
		t.Errorf("unexpected kernel string: %q", k)
	}
}
