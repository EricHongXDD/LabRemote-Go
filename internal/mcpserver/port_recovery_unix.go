//go:build !windows

package mcpserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func processImagePath(pid int) (string, error) {
	procPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	if path, err := os.Readlink(procPath); err == nil {
		return path, nil
	}
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func findLabRemoteProcessByPort(ctx context.Context, port int) (int, error) {
	command := exec.CommandContext(ctx, "lsof", "-nP", "-a", "-iTCP:"+itoa(port), "-sTCP:LISTEN", "-t")
	output, err := command.Output()
	if err != nil {
		return 0, nil
	}
	for _, value := range strings.Fields(string(output)) {
		pid, parseErr := strconv.Atoi(value)
		if parseErr != nil || pid == os.Getpid() {
			continue
		}
		executable, imageErr := processImagePath(pid)
		if imageErr == nil && isLabRemoteImage(executable) {
			return pid, nil
		}
	}
	return 0, nil
}

func terminateProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}
