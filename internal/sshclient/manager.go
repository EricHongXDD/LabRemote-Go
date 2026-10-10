package sshclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type profileRuntime struct {
	mu             sync.Mutex
	connectGate    chan struct{}
	generation     uint64
	client         *ssh.Client
	activeCommands atomic.Int32
}

type Dialer interface {
	Connect(ctx context.Context, profileID string) (model.VPNStatus, error)
	DialContext(ctx context.Context, profileID, network, address string) (net.Conn, error)
}

type terminalSession struct {
	id        string
	profileID string
	owner     string
	remotePID int
	client    *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	buffer    *RingBuffer
	sequence  atomic.Uint64
	closed    atomic.Bool
}

type Manager struct {
	repository profile.Repository
	secrets    secrets.Store
	knownHosts *KnownHosts
	events     events.Sink
	dialer     Dialer
	mu         sync.RWMutex
	runtimes   map[string]*profileRuntime
	sessions   map[string]*terminalSession
	uploadMu   sync.RWMutex
	uploads    map[string]*uploadJob
	downloadMu sync.RWMutex
	downloads  map[string]*downloadJob
}

func NewManager(repository profile.Repository, secretStore secrets.Store, knownHosts *KnownHosts, sink events.Sink, dialer Dialer) *Manager {
	return &Manager{
		repository: repository,
		secrets:    secretStore,
		knownHosts: knownHosts,
		events:     sink,
		dialer:     dialer,
		runtimes:   make(map[string]*profileRuntime),
		sessions:   make(map[string]*terminalSession),
		uploads:    make(map[string]*uploadJob),
		downloads:  make(map[string]*downloadJob),
	}
}

func (m *Manager) runtime(profileID string) *profileRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.runtimes[profileID]
	if value == nil {
		value = &profileRuntime{connectGate: make(chan struct{}, 1)}
		m.runtimes[profileID] = value
	}
	return value
}

func (m *Manager) Connect(ctx context.Context, profileID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	runtime := m.runtime(profileID)
	// 连接串行化使用可取消的入口，状态锁只保护内存，不能覆盖网络等待。
	select {
	case runtime.connectGate <- struct{}{}:
		defer func() { <-runtime.connectGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	runtime.mu.Lock()
	if runtime.client != nil {
		runtime.mu.Unlock()
		return nil
	}
	generation := runtime.generation
	runtime.mu.Unlock()
	client, err := m.dialSSH(ctx, profileID)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	if runtime.generation != generation || ctx.Err() != nil {
		runtime.mu.Unlock()
		_ = client.Close()
		return model.NewAppError("SSH_CONNECT_CANCELLED", "SSH 连接已取消", "ssh_connect", true)
	}
	runtime.client = client
	runtime.mu.Unlock()
	go m.watchClient(profileID, runtime, client)
	go m.keepClientAlive(profileID, client)
	m.events.Emit("ssh:status", map[string]any{"profile_id": profileID, "connected": true})
	return nil
}

func (m *Manager) dialSSH(ctx context.Context, profileID string) (*ssh.Client, error) {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if _, err := m.dialer.Connect(ctx, profileID); err != nil {
		return nil, err
	}
	authMethods, err := m.authenticationMethods(ctx, value)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(strings.Trim(value.SSH.ServerAddress, "[]"), strconv.Itoa(int(value.SSH.Port)))
	connection, err := m.dialer.DialContext(ctx, profileID, "tcp", address)
	if err != nil {
		var appError *model.AppError
		if errors.As(err, &appError) {
			return nil, appError
		}
		return nil, model.NewAppError("SSH_PORT_UNREACHABLE", "无法访问 SSH 服务器端口", "ssh_probe", true).WithDetails(map[string]any{"address": address})
	}
	connected := false
	defer func() {
		if !connected {
			connection.Close()
		}
	}()
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	config := &ssh.ClientConfig{
		User:            value.SSH.Username,
		Auth:            authMethods,
		HostKeyCallback: m.knownHosts.Callback(profileID),
		Timeout:         15 * time.Second,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		var appError *model.AppError
		if errors.As(err, &appError) {
			return nil, appError
		}
		var networkError net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
			return nil, model.NewAppError("SSH_HANDSHAKE_TIMEOUT", "SSH 端口已连通，但握手等待超时，请检查网络和服务器状态", "ssh_auth", true).WithDetails(map[string]any{"reason": err.Error()})
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, model.NewAppError("SSH_AUTH_FAILED", "SSH 握手或身份认证失败", "ssh_auth", false).WithDetails(map[string]any{"reason": err.Error()})
	}
	_ = connection.SetDeadline(time.Time{})
	connected = true
	return ssh.NewClient(clientConnection, channels, requests), nil
}

func (m *Manager) authenticationMethods(ctx context.Context, value model.ConnectionProfile) ([]ssh.AuthMethod, error) {
	if value.SSH.EffectiveAuthMethod() == model.SSHAuthPassword {
		password, err := m.secrets.Get(ctx, model.SSHPasswordKey(value.ID))
		if err != nil {
			return nil, model.NewAppError("SECRET_NOT_FOUND", "未找到 SSH 密码", "ssh_auth", false)
		}
		defer secrets.Zero(password)
		return []ssh.AuthMethod{ssh.Password(string(password))}, nil
	}
	path, err := m.secrets.Get(ctx, model.SSHPrivateKeyPathKey(value.ID))
	if err != nil {
		return nil, model.NewAppError("SSH_PRIVATE_KEY_NOT_FOUND", "未找到已保存的 SSH 私钥文件", "ssh_auth", false)
	}
	defer secrets.Zero(path)
	passphrase, err := m.secrets.Get(ctx, model.SSHPrivateKeyPassphraseKey(value.ID))
	if err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return nil, model.NewAppError("SECRET_NOT_FOUND", "无法读取 SSH 私钥口令", "ssh_auth", false)
	}
	defer secrets.Zero(passphrase)
	signer, _, err := LoadPrivateKeyFile(string(path), passphrase)
	if err != nil {
		return nil, err
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

func (m *Manager) DialWebContext(ctx context.Context, profileID, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, model.NewAppError("BROWSER_TARGET_DENIED", "浏览器代理仅允许 TCP 访问", "browser_proxy", false)
	}
	if err := m.Connect(ctx, profileID); err != nil {
		return nil, err
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return nil, model.NewAppError("SSH_NOT_CONNECTED", "SSH 跳转连接尚未建立", "browser_proxy", true)
	}
	connection, err := client.DialContext(ctx, "tcp", address)
	if err == nil {
		return connection, nil
	}
	if keepaliveErr := m.probeClient(ctx, profileID, client); keepaliveErr == nil {
		return nil, browserTargetError(address, err)
	}
	// SSH 传输已失效时只淘汰本次使用的旧客户端，避免并发请求关闭刚恢复的新连接。
	m.invalidateClientIf(profileID, client)
	if reconnectErr := m.Connect(ctx, profileID); reconnectErr != nil {
		return nil, model.NewAppError("BROWSER_RECONNECT_FAILED", "网页访问连接已断开，自动恢复失败", "browser_proxy", true).WithDetails(map[string]any{"reason": reconnectErr.Error()})
	}
	runtime.mu.Lock()
	client = runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return nil, model.NewAppError("BROWSER_RECONNECT_FAILED", "网页访问连接已断开，自动恢复失败", "browser_proxy", true)
	}
	connection, err = client.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, browserTargetError(address, err)
	}
	return connection, nil
}

func browserTargetError(address string, err error) error {
	return model.NewAppError("BROWSER_TARGET_UNREACHABLE", "SSH 跳转服务器无法访问浏览目标", "browser_proxy", true).WithDetails(map[string]any{
		"address": address, "reason": err.Error(),
	})
}

func (m *Manager) AcceptHostKey(profileID, fingerprint string) error {
	return m.knownHosts.AcceptPending(profileID, fingerprint)
}

func (m *Manager) OpenTerminal(ctx context.Context, profileID string, cols, rows int, owner string) (string, error) {
	if cols < 20 || cols > 1000 || rows < 5 || rows > 500 {
		return "", model.NewAppError("SSH_SESSION_FAILED", "终端尺寸无效", "ssh_terminal", false)
	}
	if err := m.Connect(ctx, profileID); err != nil {
		return "", err
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return "", model.NewAppError("SSH_SESSION_FAILED", "SSH 客户端未连接", "ssh_terminal", true)
	}
	setupContext, cancelSetup := context.WithTimeout(ctx, 15*time.Second)
	defer cancelSetup()
	sshSession, err := m.newSession(setupContext, profileID, client)
	if err != nil {
		return "", sessionFailure(setupContext, err, "创建 SSH 会话失败", "ssh_terminal")
	}
	stdin, err := sshSession.StdinPipe()
	if err != nil {
		sshSession.Close()
		return "", model.NewAppError("SSH_SESSION_FAILED", "创建终端输入通道失败", "ssh_terminal", true)
	}
	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		sshSession.Close()
		return "", model.NewAppError("SSH_SESSION_FAILED", "创建终端输出通道失败", "ssh_terminal", true)
	}
	stderr, err := sshSession.StderrPipe()
	if err != nil {
		sshSession.Close()
		return "", model.NewAppError("SSH_SESSION_FAILED", "创建终端错误通道失败", "ssh_terminal", true)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := m.sessionRequest(setupContext, profileID, client, func() error {
		return sshSession.RequestPty("xterm-256color", rows, cols, modes)
	}); err != nil {
		sshSession.Close()
		return "", sessionFailure(setupContext, err, "远程服务器拒绝 PTY 请求", "ssh_terminal")
	}
	// Shell 启动也可能等待服务端响应，取消时必须能释放调用入口。
	var trackedStdout io.Reader
	var remotePID int
	err = m.sessionRequest(setupContext, profileID, client, func() error {
		var startErr error
		trackedStdout, remotePID, startErr = startTrackedShell(setupContext, sshSession, stdout)
		return startErr
	})
	if err != nil {
		sshSession.Close()
		return "", sessionFailure(setupContext, err, "启动远程 Shell 失败", "ssh_terminal")
	}
	sessionID := owner + "-session-" + uuid.NewString()
	entry := &terminalSession{
		id: sessionID, profileID: profileID, owner: owner, remotePID: remotePID, client: client, session: sshSession, stdin: stdin,
		buffer: NewRingBuffer(2 * 1024 * 1024),
	}
	m.mu.Lock()
	m.sessions[sessionID] = entry
	m.mu.Unlock()
	go m.readTerminal(entry, trackedStdout)
	go m.readTerminal(entry, stderr)
	go m.waitTerminal(entry)
	return sessionID, nil
}

func (m *Manager) readTerminal(session *terminalSession, reader io.Reader) {
	buffer := make([]byte, 16*1024)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			value := append([]byte(nil), buffer[:count]...)
			session.buffer.Append(value)
			if session.owner == "ui" {
				m.events.Emit("terminal:data", model.TerminalChunk{
					SessionID:  session.id,
					Sequence:   session.sequence.Add(1),
					DataBase64: base64.StdEncoding.EncodeToString(value),
				})
			}
		}
		if err != nil {
			return
		}
	}
}

func (m *Manager) waitTerminal(session *terminalSession) {
	err := session.session.Wait()
	errText := ""
	if err != nil && !errors.Is(err, io.EOF) {
		errText = err.Error()
	}
	session.buffer.Close(errText)
	session.closed.Store(true)
	m.events.Emit("terminal:closed", map[string]any{"session_id": session.id, "reason": errText})
	// 保留已关闭会话的有界缓冲区一小段时间，让 MCP 客户端读取最后输出和退出状态。
	time.AfterFunc(5*time.Minute, func() {
		m.mu.Lock()
		if current := m.sessions[session.id]; current == session {
			delete(m.sessions, session.id)
		}
		m.mu.Unlock()
	})
}

func (m *Manager) WriteTerminal(ctx context.Context, sessionID string, data []byte) error {
	session, err := m.getSession(sessionID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return m.sessionRequest(ctx, session.profileID, session.client, func() error {
		_, err := session.stdin.Write(data)
		return err
	})
}

func (m *Manager) ResizeTerminal(ctx context.Context, sessionID string, cols, rows int) error {
	if cols < 20 || rows < 5 {
		return model.NewAppError("SSH_SESSION_FAILED", "终端尺寸无效", "ssh_terminal", false)
	}
	session, err := m.getSession(sessionID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return m.sessionRequest(ctx, session.profileID, session.client, func() error { return session.session.WindowChange(rows, cols) })
}

func (m *Manager) CloseSession(_ context.Context, sessionID string) error {
	session, err := m.getSession(sessionID)
	if err != nil {
		return err
	}
	if session.closed.CompareAndSwap(false, true) {
		session.buffer.Close("会话已关闭")
		go session.session.Close()
		return nil
	}
	return nil
}

func (m *Manager) ReadTerminal(ctx context.Context, sessionID string, cursor uint64, maxBytes int, wait time.Duration) (model.SessionReadResult, error) {
	session, err := m.getSession(sessionID)
	if err != nil {
		return model.SessionReadResult{}, err
	}
	data, next, open, truncated, errText := session.buffer.Read(ctx, cursor, maxBytes, wait)
	return model.SessionReadResult{
		Cursor:     next,
		DataBase64: base64.StdEncoding.EncodeToString(data),
		Open:       open,
		Truncated:  truncated,
		Error:      errText,
	}, nil
}

func (m *Manager) Exec(ctx context.Context, request model.ExecRequest) (model.ExecResult, error) {
	if request.Command == "" {
		return model.ExecResult{}, model.NewAppError("PROFILE_INVALID", "命令不能为空", "ssh_exec", false)
	}
	if request.Timeout <= 0 {
		request.Timeout = 30 * time.Second
	}
	if request.Timeout > 5*time.Minute {
		request.Timeout = 5 * time.Minute
	}
	if request.MaxOutputBytes <= 0 {
		request.MaxOutputBytes = 1024 * 1024
	}
	if request.MaxOutputBytes > 4*1024*1024 {
		request.MaxOutputBytes = 4 * 1024 * 1024
	}
	// 超时覆盖连接、会话创建和命令启动，不能只限制最后的 Wait。
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	start := time.Now()
	if err := m.Connect(ctx, request.ProfileID); err != nil {
		if ctx.Err() != nil {
			return model.ExecResult{}, commandTimeout()
		}
		return model.ExecResult{}, err
	}
	runtime := m.runtime(request.ProfileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return model.ExecResult{}, model.NewAppError("SSH_SESSION_FAILED", "SSH 客户端未连接", "ssh_exec", true)
	}
	session, err := m.newSession(ctx, request.ProfileID, client)
	if err != nil {
		if ctx.Err() != nil {
			return model.ExecResult{}, commandTimeout()
		}
		return model.ExecResult{}, sessionFailure(ctx, err, "创建命令会话失败", "ssh_exec")
	}
	defer func() { go session.Close() }()
	runtime.activeCommands.Add(1)
	defer runtime.activeCommands.Add(-1)
	stdout := NewLimitedWriter(request.MaxOutputBytes)
	stderr := NewLimitedWriter(request.MaxOutputBytes)
	session.Stdout = stdout
	session.Stderr = stderr
	if err := m.sessionRequest(ctx, request.ProfileID, client, func() error { return session.Start(request.Command) }); err != nil {
		if ctx.Err() != nil {
			return model.ExecResult{}, commandTimeout()
		}
		return model.ExecResult{}, model.NewAppError("SSH_SESSION_FAILED", "发送 SSH 命令失败", "ssh_exec", true)
	}
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-ctx.Done():
		return model.ExecResult{}, commandTimeout()
	}
	exitCode := 0
	if waitErr != nil {
		var exitError *ssh.ExitError
		if errors.As(waitErr, &exitError) {
			exitCode = exitError.ExitStatus()
		} else {
			return model.ExecResult{}, fmt.Errorf("SSH 命令会话失败: %w", waitErr)
		}
	}
	return model.ExecResult{
		ExitCode:   exitCode,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMS: time.Since(start).Milliseconds(),
		Truncated:  stdout.Truncated() || stderr.Truncated(),
	}, nil
}

func (m *Manager) Counts(profileID string) (uiSessions, mcpSessions, activeCommands int) {
	m.mu.RLock()
	for _, session := range m.sessions {
		if session.profileID != profileID || session.closed.Load() {
			continue
		}
		if session.owner == "ui" {
			uiSessions++
		} else if session.owner == "mcp" {
			mcpSessions++
		}
	}
	runtime := m.runtimes[profileID]
	m.mu.RUnlock()
	if runtime != nil {
		activeCommands = int(runtime.activeCommands.Load())
	}
	return
}

func (m *Manager) CloseProfileSessions(ctx context.Context, profileID, owner string) {
	m.mu.RLock()
	ids := make([]string, 0)
	for id, session := range m.sessions {
		if session.profileID == profileID && (owner == "" || session.owner == owner) {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range ids {
		_ = m.CloseSession(ctx, id)
	}
}

func (m *Manager) CloseProfile(ctx context.Context, profileID string) {
	m.CancelProfileUploads(profileID)
	m.CancelProfileDownloads(profileID)
	m.waitProfileTransfers(ctx, profileID, 3*time.Second)
	m.CloseProfileSessions(ctx, profileID, "")
	m.invalidateClient(profileID)
}

func (m *Manager) waitProfileTransfers(ctx context.Context, profileID string, maximum time.Duration) {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.ActiveUploadCount(profileID)+m.ActiveDownloadCount(profileID) == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) CloseOwnerSessions(ctx context.Context, owner string) {
	m.mu.RLock()
	ids := make([]string, 0)
	for id, session := range m.sessions {
		if session.owner == owner {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range ids {
		_ = m.CloseSession(ctx, id)
	}
}

func (m *Manager) CloseAll(ctx context.Context) {
	m.CancelAllUploads()
	m.CancelAllDownloads()
	m.mu.RLock()
	profileIDs := make([]string, 0, len(m.runtimes))
	for profileID := range m.runtimes {
		profileIDs = append(profileIDs, profileID)
	}
	m.mu.RUnlock()
	for _, profileID := range profileIDs {
		m.waitProfileTransfers(ctx, profileID, 3*time.Second)
	}
	m.CloseOwnerSessions(ctx, "ui")
	m.CloseOwnerSessions(ctx, "mcp")
	for _, profileID := range profileIDs {
		m.invalidateClient(profileID)
	}
}

func (m *Manager) IsConnected(profileID string) bool {
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.client != nil
}

func (m *Manager) getSession(sessionID string) (*terminalSession, error) {
	m.mu.RLock()
	session := m.sessions[sessionID]
	m.mu.RUnlock()
	if session == nil {
		return nil, model.NewAppError("MCP_SESSION_NOT_FOUND", "交互会话不存在", "ssh_terminal", false)
	}
	return session, nil
}

func (m *Manager) invalidateClient(profileID string) {
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.client = nil
	runtime.generation++
	runtime.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	m.events.Emit("ssh:status", map[string]any{"profile_id": profileID, "connected": false})
}

func (m *Manager) invalidateClientIf(profileID string, expected *ssh.Client) {
	if expected == nil {
		return
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	matched := runtime.client == expected
	if matched {
		runtime.client = nil
	}
	runtime.mu.Unlock()
	_ = expected.Close()
	if matched {
		m.events.Emit("ssh:status", map[string]any{"profile_id": profileID, "connected": false})
	}
}

func (m *Manager) watchClient(profileID string, runtime *profileRuntime, client *ssh.Client) {
	_ = client.Wait()
	runtime.mu.Lock()
	if runtime.client != client {
		runtime.mu.Unlock()
		return
	}
	runtime.client = nil
	runtime.mu.Unlock()
	m.events.Emit("ssh:status", map[string]any{"profile_id": profileID, "connected": false})
}
