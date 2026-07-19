//go:build windows && legacy_ras

package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/EricHongXDD/LabRemote-Go/internal/logging"
)

const powerShellPath = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

func runPowerShellJSON(ctx context.Context, script string, input any) (string, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("序列化 PowerShell 输入失败: %w", err)
	}
	command := exec.CommandContext(ctx, powerShellPath, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Stdin = bytes.NewReader(data)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("PowerShell 执行失败: %w: %s", err, logging.Redact(stderr.String()))
	}
	return logging.Redact(stdout.String()), nil
}
