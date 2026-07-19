package sshclient

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"golang.org/x/crypto/ssh"
)

const trackedShellCommand = `printf '\036LABREMOTE_PID=%d\037' "$$"; exec "${SHELL:-/bin/sh}" -l`

type trackedShellResult struct {
	reader io.Reader
	pid    int
	err    error
}

func startTrackedShell(ctx context.Context, session *ssh.Session, stdout io.Reader) (io.Reader, int, error) {
	if err := session.Start(trackedShellCommand); err != nil {
		return nil, 0, err
	}
	resultChannel := make(chan trackedShellResult, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		value, err := reader.ReadString('\x1f')
		if err != nil {
			resultChannel <- trackedShellResult{err: err}
			return
		}
		start := strings.LastIndex(value, "\x1eLABREMOTE_PID=")
		if start < 0 {
			resultChannel <- trackedShellResult{err: fmt.Errorf("远程 Shell 未返回进程标识")}
			return
		}
		pidText := strings.TrimSuffix(value[start+len("\x1eLABREMOTE_PID="):], "\x1f")
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid <= 0 {
			resultChannel <- trackedShellResult{err: fmt.Errorf("远程 Shell 进程标识无效")}
			return
		}
		prefix := []byte(value[:start])
		resultChannel <- trackedShellResult{reader: io.MultiReader(bytes.NewReader(prefix), reader), pid: pid}
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case result := <-resultChannel:
		return result.reader, result.pid, result.err
	case <-ctx.Done():
		_ = session.Close()
		return nil, 0, ctx.Err()
	case <-timer.C:
		_ = session.Close()
		return nil, 0, fmt.Errorf("等待远程 Shell 启动超时")
	}
}

func (m *Manager) TerminalWorkingDirectory(ctx context.Context, sessionID string) (string, error) {
	session, err := m.getSession(sessionID)
	if err != nil {
		return "", err
	}
	if session.remotePID <= 0 || session.closed.Load() {
		return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "当前终端目录不可用", "ssh_terminal", true)
	}
	runtime := m.runtime(session.profileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "SSH 连接已断开", "ssh_terminal", true)
	}
	query, err := client.NewSession()
	if err != nil {
		return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "无法查询当前终端目录", "ssh_terminal", true)
	}
	defer query.Close()
	command := fmt.Sprintf("readlink -e /proc/%d/cwd", session.remotePID)
	type queryResult struct {
		output []byte
		err    error
	}
	resultChannel := make(chan queryResult, 1)
	go func() {
		output, runErr := query.Output(command)
		resultChannel <- queryResult{output: output, err: runErr}
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		_ = query.Close()
		return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "查询当前终端目录已取消", "ssh_terminal", true)
	case <-timer.C:
		_ = query.Close()
		return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "查询当前终端目录超时", "ssh_terminal", true)
	case result := <-resultChannel:
		value := strings.TrimSpace(string(result.output))
		if result.err != nil || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\r\n\x00") || len(value) > 4096 {
			return "", model.NewAppError("TERMINAL_DIRECTORY_UNAVAILABLE", "远端系统不支持读取当前终端目录", "ssh_terminal", false)
		}
		return value, nil
	}
}
