package common

import (
	"fmt"
	"os"
	"strings"
)

type ProcInfo struct {
	PID     int
	Name    string
	Cmdline string
}

func EnumerateProcesses() []ProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var procs []ProcInfo
	for _, e := range entries {
		pid := 0
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid == 0 {
			continue
		}
		info := readProcInfo(pid)
		if info != nil {
			procs = append(procs, *info)
		}
	}
	return procs
}

func readProcInfo(pid int) *ProcInfo {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}
	statStr := string(stat)
	parts := strings.SplitN(statStr, " ", 3)
	name := ""
	if len(parts) >= 2 {
		name = strings.Trim(parts[1], "()")
	}
	cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
	if cmdStr == "" {
		cmdStr = name
	}
	return &ProcInfo{PID: pid, Name: name, Cmdline: cmdStr}
}
