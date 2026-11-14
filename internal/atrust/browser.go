package atrust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// browserExecutable 只启动专门用于本次认证的浏览器，不调用 VPN 客户端。
func browserExecutable() string {
	var paths []string
	for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
		if root == "" {
			continue
		}
		paths = append(paths, filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"), filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"))
	}
	for _, name := range []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			paths = append(paths, path)
		}
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Error     *struct {
		Code int `json:"code"`
	} `json:"error,omitempty"`
}

// browserCallback 等待用户手动认证，仅截获网关回调，不读取密码、键盘或其他浏览器会话。
func browserCallback(ctx context.Context, loginURL, callbackURL string) (string, error) {
	executable := browserExecutable()
	if executable == "" {
		return "", fmt.Errorf("未找到 Edge 或 Chrome，无法打开独立认证窗口")
	}
	directory, err := os.MkdirTemp("", "labremote-atrust-auth-")
	if err != nil {
		return "", fmt.Errorf("无法创建临时认证环境")
	}
	defer os.RemoveAll(directory)
	browserContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(browserContext, executable, "--user-data-dir="+directory, "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", "--no-startup-window")
	if command.Start() != nil {
		return "", fmt.Errorf("无法启动独立认证窗口")
	}
	processDone := make(chan struct{})
	go func() { _ = command.Wait(); close(processDone) }()
	defer func() {
		cancel()
		select {
		case <-processDone:
		case <-time.After(3 * time.Second):
		}
	}()
	var endpoint string
	startup := time.NewTimer(15 * time.Second)
	defer startup.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
ready:
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-processDone:
			return "", fmt.Errorf("认证窗口已关闭")
		case <-startup.C:
			return "", fmt.Errorf("认证窗口启动超时")
		case <-ticker.C:
			data, readErr := os.ReadFile(filepath.Join(directory, "DevToolsActivePort"))
			if readErr != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 2 {
				continue
			}
			port, parseErr := strconv.Atoi(strings.TrimSpace(lines[0]))
			if parseErr != nil || port < 1 || port > 65535 || !strings.HasPrefix(strings.TrimSpace(lines[1]), "/devtools/browser/") {
				continue
			}
			endpoint = "ws://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + strings.TrimSpace(lines[1])
			break ready
		}
	}
	connection, _, err := websocket.DefaultDialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("无法连接本次认证窗口")
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var writeMu sync.Mutex
	sequence := 0
	send := func(method, session string, parameters any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		sequence++
		encoded, _ := json.Marshal(parameters)
		_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return connection.WriteJSON(cdpMessage{ID: sequence, Method: method, Params: encoded, SessionID: session})
	}
	defer func() { _ = send("Browser.close", "", map[string]any{}) }()
	if send("Target.setAutoAttach", "", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}) != nil {
		return "", fmt.Errorf("无法初始化认证窗口")
	}
	if send("Target.createTarget", "", map[string]any{"url": "about:blank", "newWindow": true}) != nil {
		return "", fmt.Errorf("无法打开认证页面")
	}
	var targetSession string
	stage := "等待认证页面"
	for {
		var message cdpMessage
		if readErr := connection.ReadJSON(&message); readErr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("认证窗口已关闭或连接中断（%s；%v）", stage, readErr)
		}
		if message.Error != nil {
			return "", fmt.Errorf("认证窗口接口初始化失败（%d）", message.Error.Code)
		}
		switch message.Method {
		case "Target.attachedToTarget":
			stage = "初始化认证页面"
			var event struct {
				SessionID string `json:"sessionId"`
				Target    struct {
					Type string `json:"type"`
				} `json:"targetInfo"`
			}
			if json.Unmarshal(message.Params, &event) != nil {
				continue
			}
			if event.Target.Type != "page" {
				_ = send("Runtime.runIfWaitingForDebugger", event.SessionID, map[string]any{})
				continue
			}
			if targetSession != "" {
				_ = send("Runtime.runIfWaitingForDebugger", event.SessionID, map[string]any{})
				continue
			}
			targetSession = event.SessionID
			if err := send("Fetch.enable", targetSession, map[string]any{"patterns": []map[string]string{{"urlPattern": callbackURL + "*", "requestStage": "Request"}}}); err != nil {
				return "", err
			}
			_ = send("Runtime.runIfWaitingForDebugger", targetSession, map[string]any{})
			_ = send("Page.navigate", targetSession, map[string]any{"url": loginURL})
			stage = "等待网页回调"
		case "Fetch.requestPaused":
			var event struct {
				ID      string `json:"requestId"`
				Request struct {
					URL    string `json:"url"`
					Method string `json:"method"`
				} `json:"request"`
			}
			if json.Unmarshal(message.Params, &event) != nil {
				continue
			}
			if message.SessionID != targetSession || event.Request.Method != "GET" {
				_ = send("Fetch.continueRequest", message.SessionID, map[string]any{"requestId": event.ID})
				continue
			}
			if !validCallback(event.Request.URL, callbackURL) {
				_ = send("Fetch.failRequest", message.SessionID, map[string]any{"requestId": event.ID, "errorReason": "BlockedByClient"})
				return "", errors.New("认证回调与当前入口不匹配")
			}
			html := base64.StdEncoding.EncodeToString([]byte("<!doctype html><meta charset=utf-8><title>LabRemote</title><p>认证回调已交给 LabRemote，请返回应用。</p>"))
			_ = send("Fetch.fulfillRequest", targetSession, map[string]any{"requestId": event.ID, "responseCode": 200, "responseHeaders": []map[string]string{{"name": "Content-Type", "value": "text/html; charset=utf-8"}}, "body": html})
			return event.Request.URL, nil
		}
	}
}
