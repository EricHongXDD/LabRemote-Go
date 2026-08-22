//go:build windows

package mcpserver

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

func processImagePath(pid int) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func findLabRemoteProcessByPort(ctx context.Context, port int) (int, error) {
	output, err := exec.CommandContext(ctx, "netstat.exe", "-ano", "-p", "tcp").Output()
	if err != nil {
		return 0, nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") || !strings.EqualFold(fields[len(fields)-2], "LISTENING") {
			continue
		}
		_, localPort, splitErr := net.SplitHostPort(fields[1])
		if splitErr != nil || localPort != strconv.Itoa(port) {
			continue
		}
		pid, parseErr := strconv.Atoi(fields[len(fields)-1])
		if parseErr != nil || pid <= 0 || pid == os.Getpid() {
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
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.TerminateProcess(handle, 1)
}
