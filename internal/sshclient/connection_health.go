package sshclient

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func commandTimeout() error {
	return model.NewAppError("SSH_COMMAND_TIMEOUT", "SSH 命令已取消或执行超时（包含连接与启动阶段）", "ssh_exec", true)
}

// sessionRequest 为没有原生上下文支持的 SSH 请求提供退出边界。
func (m *Manager) sessionRequest(ctx context.Context, profileID string, client *ssh.Client, request func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- request() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// 仅淘汰本次等待的客户端，旧请求不得关闭并发恢复的新连接。
		m.invalidateClientIf(profileID, client)
		return ctx.Err()
	}
}

func (m *Manager) newSession(ctx context.Context, profileID string, client *ssh.Client) (*ssh.Session, error) {
	var session *ssh.Session
	err := m.sessionRequest(ctx, profileID, client, func() error {
		var err error
		session, err = client.NewSession()
		if session != nil && ctx.Err() != nil {
			_ = session.Close()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (m *Manager) probeClient(ctx context.Context, profileID string, client *ssh.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return m.sessionRequest(ctx, profileID, client, func() error {
		// 请求回复才能证明远端仍可响应；服务端不支持时返回 false 也表示链路正常。
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		return err
	})
}

func (m *Manager) keepClientAlive(profileID string, client *ssh.Client) {
	done := make(chan struct{})
	go func() { _ = client.Wait(); close(done) }()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := m.probeClient(context.Background(), profileID, client); err != nil {
				m.invalidateClientIf(profileID, client)
				return
			}
		}
	}
}

type transferActivity struct {
	last atomic.Int64
}

type transferReader struct {
	io.Reader
	activity *transferActivity
}

func (r transferReader) Read(buffer []byte) (int, error) {
	n, err := r.Reader.Read(buffer)
	if n > 0 {
		r.activity.last.Store(time.Now().UnixNano())
	}
	return n, err
}

type transferWriter struct {
	io.WriteCloser
	activity *transferActivity
}

func (w transferWriter) Write(buffer []byte) (int, error) {
	n, err := w.WriteCloser.Write(buffer)
	if n > 0 {
		w.activity.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func watchTransfer(ctx context.Context, activity *transferActivity, idle time.Duration, closeTransport func()) {
	ticker := time.NewTicker(idle / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			closeTransport()
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, activity.last.Load())) >= idle {
				closeTransport()
				return
			}
		}
	}
}

// newSFTPClient 使用独立的 SSH 传输，使取消或停滞清理不影响已有终端和命令。
func (m *Manager) newSFTPClient(ctx context.Context, profileID string, options ...sftp.ClientOption) (*sftp.Client, func(), error) {
	setupContext, cancelSetup := context.WithTimeout(ctx, 45*time.Second)
	defer cancelSetup()
	transport, err := m.dialSSH(setupContext, profileID)
	if err != nil {
		return nil, nil, err
	}
	stopSetup := context.AfterFunc(setupContext, func() { _ = transport.Close() })
	defer stopSetup()
	ready := false
	defer func() {
		if !ready {
			_ = transport.Close()
		}
	}()
	session, err := transport.NewSession()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	// 子系统请求不启动 Session 的标准输出复制器，必须主动排空错误输出。
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	if err := session.RequestSubsystem("sftp"); err != nil {
		if setupContext.Err() != nil {
			return nil, nil, setupContext.Err()
		}
		return nil, nil, model.NewAppError("SFTP_UNAVAILABLE", "远端 SSH 服务未提供 SFTP 子系统", "sftp_connect", false)
	}
	activity := &transferActivity{}
	activity.last.Store(time.Now().UnixNano())
	client, err := sftp.NewClientPipe(transferReader{stdout, activity}, transferWriter{stdin, activity}, options...)
	if err != nil {
		return nil, nil, err
	}
	if setupContext.Err() != nil {
		return nil, nil, setupContext.Err()
	}
	watchContext, stopWatch := context.WithCancel(ctx)
	go watchTransfer(watchContext, activity, 60*time.Second, func() { _ = transport.Close() })
	ready = true
	return client, func() {
		stopWatch()
		// 先关闭底层传输，确保 SFTP 清理也不会被无响应的远端卡住。
		_ = transport.Close()
		_ = client.Close()
	}, nil
}
