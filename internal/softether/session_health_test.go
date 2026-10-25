package softether

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// cappedDeadlineConn 将测试中的写超时缩短，避免回归测试等待生产环境的十五秒。
type cappedDeadlineConn struct{ net.Conn }

func (c cappedDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if maximum := time.Now().Add(100 * time.Millisecond); maximum.Before(deadline) {
		deadline = maximum
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func healthTestSession(t *testing.T) (*Session, *tls.Conn) {
	t.Helper()
	certificateServer := httptest.NewTLSServer(nil)
	certificates := certificateServer.TLS.Certificates
	certificateServer.Close()
	clientRaw, serverRaw := net.Pipe()
	server := tls.Server(serverRaw, &tls.Config{Certificates: certificates, MaxVersion: tls.VersionTLS12})
	// 仅本地测试使用临时证书；生产连接仍执行指纹验证。
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	_ = clientRaw.SetDeadline(time.Now().Add(3 * time.Second))
	_ = serverRaw.SetDeadline(time.Now().Add(3 * time.Second))
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	_ = clientRaw.SetDeadline(time.Time{})
	_ = serverRaw.SetDeadline(time.Time{})
	session := &Session{
		raw: cappedDeadlineConn{clientRaw}, secure: client, reader: bufio.NewReader(client),
		frames: make(chan []byte, 256), outbound: make(chan []byte, 256), done: make(chan struct{}),
	}
	t.Cleanup(func() { _ = clientRaw.Close(); _ = serverRaw.Close(); _ = session.Close() })
	return session, server
}

func requireSessionTimeout(t *testing.T, session *Session) {
	t.Helper()
	select {
	case <-session.Done():
		var networkError net.Error
		if !errors.As(session.Err(), &networkError) || !networkError.Timeout() {
			t.Fatalf("未保留网络超时原因: %v", session.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("静默隧道未在期限内关闭")
	}
}

func TestSessionReadTimeoutReleasesSilentTunnel(t *testing.T) {
	session, _ := healthTestSession(t)
	go session.readLoop(100 * time.Millisecond)
	requireSessionTimeout(t, session)
}

func TestSessionKeepaliveRefreshesReadDeadline(t *testing.T) {
	session, server := healthTestSession(t)
	go session.readLoop(300 * time.Millisecond)
	// 持续保活超过单次读期限，空闲但健康的隧道必须保持可用。
	for i := 0; i < 8; i++ {
		_ = server.SetWriteDeadline(time.Now().Add(time.Second))
		if err := binary.Write(server, binary.BigEndian, keepAliveMagic); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(server, binary.BigEndian, uint32(0)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-session.Done():
			t.Fatalf("正常保活被误判为断线: %v", session.Err())
		case <-time.After(60 * time.Millisecond):
		}
	}
	requireSessionTimeout(t, session)
}

func TestSessionWriteTimeoutReleasesBlockedTunnel(t *testing.T) {
	session, _ := healthTestSession(t)
	// 对端不读取任何数据，验证实际 TLS 写入也能被期限打断。
	session.outbound <- make([]byte, 1500)
	go session.writeLoop()
	requireSessionTimeout(t, session)
}
