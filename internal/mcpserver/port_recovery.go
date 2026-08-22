package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type ownerRecord struct {
	PID        int    `json:"pid"`
	Port       int    `json:"port"`
	Executable string `json:"executable"`
}

func (c *Controller) listenWithRecovery(ctx context.Context, port int) (net.Listener, error) {
	address := net.JoinHostPort("127.0.0.1", itoa(port))
	listener, err := net.Listen("tcp4", address)
	if err == nil || !isAddressInUse(err) {
		return listener, err
	}
	if reclaimErr := c.reclaimPort(ctx, port); reclaimErr != nil {
		return nil, err
	}
	for attempt := 0; attempt < 30; attempt++ {
		listener, err = net.Listen("tcp4", address)
		if err == nil {
			return listener, nil
		}
		if !isAddressInUse(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, err
}

func isAddressInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

func (c *Controller) reclaimPort(ctx context.Context, port int) error {
	if c.ownerFile != "" {
		if record, err := readOwnerRecord(c.ownerFile); err == nil && record.Port == port && record.PID > 0 && record.PID != os.Getpid() {
			if processMatchesOwner(record.PID, record.Executable) {
				if err := terminateProcess(record.PID); err == nil && waitForPortAvailable(ctx, port) == nil {
					return nil
				}
			}
		}
	}

	pid, err := findLabRemoteProcessByPort(ctx, port)
	if err != nil {
		return err
	}
	if pid <= 0 || pid == os.Getpid() {
		return errors.New("MCP 端口未找到可接管的 LabRemote 进程")
	}
	if err := terminateProcess(pid); err != nil {
		return err
	}
	return waitForPortAvailable(ctx, port)
}

func waitForPortAvailable(ctx context.Context, port int) error {
	address := net.JoinHostPort("127.0.0.1", itoa(port))
	for {
		listener, err := net.Listen("tcp4", address)
		if err == nil {
			_ = listener.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func processMatchesOwner(pid int, expectedExecutable string) bool {
	actualExecutable, err := processImagePath(pid)
	if err != nil {
		return false
	}
	if samePath(actualExecutable, expectedExecutable) {
		return true
	}
	return isLabRemoteImage(actualExecutable) && isLabRemoteImage(expectedExecutable)
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	left, _ = filepath.Abs(left)
	right, _ = filepath.Abs(right)
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func isLabRemoteImage(path string) bool {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), strings.ToLower(filepath.Ext(path)))
	return base == "labremote" || base == "labremote-go" || strings.HasPrefix(base, "labremote-")
}

func readOwnerRecord(path string) (ownerRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ownerRecord{}, err
	}
	var record ownerRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return ownerRecord{}, err
	}
	if record.PID <= 0 || record.Port < 1024 || record.Port > 65535 || record.Executable == "" {
		return ownerRecord{}, fmt.Errorf("MCP 所有权记录无效")
	}
	return record, nil
}

func (c *Controller) writeOwnerRecord(port int) {
	if c.ownerFile == "" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}
	data, err := json.Marshal(ownerRecord{PID: os.Getpid(), Port: port, Executable: executable})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.ownerFile), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(c.ownerFile, data, 0o600)
}

func (c *Controller) removeOwnerRecord(port int) {
	if c.ownerFile == "" {
		return
	}
	record, err := readOwnerRecord(c.ownerFile)
	if err != nil || record.PID != os.Getpid() || record.Port != port {
		return
	}
	_ = os.Remove(c.ownerFile)
}
