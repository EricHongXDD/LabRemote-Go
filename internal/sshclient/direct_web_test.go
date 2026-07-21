package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/browserproxy"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"golang.org/x/crypto/ssh"
)

type directTCPIPRequest struct {
	DestinationAddress string
	DestinationPort    uint32
	OriginAddress      string
	OriginPort         uint32
}

type directTCPIPServer struct {
	net.Listener
	signer     ssh.Signer
	config     *ssh.ServerConfig
	mu         sync.Mutex
	clients    map[*ssh.ServerConn]struct{}
	handshakes atomic.Int32
}

func TestDirectSSHModeBrowserProxyReachesRemoteLoopbackPort(t *testing.T) {
	internalHTTP := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Connection", "close")
		_, _ = response.Write([]byte("remote loopback through ssh"))
	}))
	defer internalHTTP.Close()
	targetURL, err := url.Parse(internalHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}

	sshServer, signer := startDirectTCPIPServer(t, "ssh-password")
	defer sshServer.Close()
	sshAddress := sshServer.Addr().(*net.TCPAddr)
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	value := model.ConnectionProfile{
		ID: "direct-web", DisplayName: "仅 SSH 网页访问", ConnectionMode: model.ConnectionModeDirectSSH,
		SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: uint16(sshAddress.Port), Username: "user"},
	}
	if err := repository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	secretStore := secrets.NewMemoryStore()
	if err := secretStore.Put(context.Background(), model.SSHPasswordKey(value.ID), []byte("ssh-password")); err != nil {
		t.Fatal(err)
	}
	knownHosts := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	if err := knownHosts.Store(HostKeyRecord{
		ProfileID: value.ID,
		Address:   net.JoinHostPort(value.SSH.ServerAddress, strconv.Itoa(int(value.SSH.Port))),
		KeyType:   signer.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
	}); err != nil {
		t.Fatal(err)
	}
	transport := vpn.NewIsolatedManager(repository, secretStore, events.Nop{})
	manager := NewManager(repository, secretStore, knownHosts, events.Nop{}, transport)
	proxy := browserproxy.NewManager(manager)
	defer func() {
		proxy.CloseAll(context.Background())
		manager.CloseAll(context.Background())
		transport.Shutdown(context.Background())
	}()

	bootstrapURL, err := proxy.Open(context.Background(), value.ID, "http://127.0.0.1:"+targetURL.Port()+"/internal")
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	response, err := client.Get(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "remote loopback through ssh" {
		t.Fatalf("仅 SSH 网页访问结果异常: status=%d body=%q", response.StatusCode, body)
	}
	firstHandshakes := sshServer.handshakes.Load()
	sshServer.CloseClients()
	response, err = client.Get(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "remote loopback through ssh" {
		t.Fatalf("SSH 断线后网页访问未自动恢复: status=%d body=%q", response.StatusCode, body)
	}
	if sshServer.handshakes.Load() <= firstHandshakes {
		t.Fatalf("SSH 断线后没有建立新连接: before=%d after=%d", firstHandshakes, sshServer.handshakes.Load())
	}
}

func TestManagerConnectsWithPrivateKey(t *testing.T) {
	keyPath, publicKey := writeTestPrivateKey(t, false, nil)
	allowedKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(allowedKey) {
			return nil, fmt.Errorf("公钥不匹配")
		}
		return nil, nil
	}}
	sshServer, signer := startDirectTCPIPServerWithConfig(t, config)
	defer sshServer.Close()
	sshAddress := sshServer.Addr().(*net.TCPAddr)
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	value := model.ConnectionProfile{
		ID: "private-key", DisplayName: "私钥 SSH", ConnectionMode: model.ConnectionModeDirectSSH,
		SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: uint16(sshAddress.Port), Username: "user", AuthMethod: model.SSHAuthPrivateKey},
	}
	if err := repository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	secretStore := secrets.NewMemoryStore()
	if err := secretStore.Put(context.Background(), model.SSHPrivateKeyPathKey(value.ID), []byte(keyPath)); err != nil {
		t.Fatal(err)
	}
	knownHosts := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	if err := knownHosts.Store(HostKeyRecord{
		ProfileID: value.ID, Address: net.JoinHostPort(value.SSH.ServerAddress, strconv.Itoa(int(value.SSH.Port))),
		KeyType: signer.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
	}); err != nil {
		t.Fatal(err)
	}
	transport := vpn.NewIsolatedManager(repository, secretStore, events.Nop{})
	manager := NewManager(repository, secretStore, knownHosts, events.Nop{}, transport)
	defer func() {
		manager.CloseAll(context.Background())
		transport.Shutdown(context.Background())
	}()
	if err := manager.Connect(context.Background(), value.ID); err != nil {
		t.Fatal(err)
	}
	if !manager.IsConnected(value.ID) {
		t.Fatal("私钥认证成功后 SSH 状态应为已连接")
	}
}

func startDirectTCPIPServer(t *testing.T, password string) (*directTCPIPServer, ssh.Signer) {
	t.Helper()
	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, provided []byte) (*ssh.Permissions, error) {
			if string(provided) != password {
				return nil, fmt.Errorf("密码错误")
			}
			return nil, nil
		},
	}
	return startDirectTCPIPServerWithConfig(t, config)
}

func startDirectTCPIPServerWithConfig(t *testing.T, config *ssh.ServerConfig) (*directTCPIPServer, ssh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &directTCPIPServer{Listener: listener, signer: signer, config: config, clients: make(map[*ssh.ServerConn]struct{})}
	go server.serve()
	return server, signer
}

func (s *directTCPIPServer) serve() {
	for {
		connection, acceptErr := s.Accept()
		if acceptErr != nil {
			return
		}
		go s.serveConnection(connection)
	}
}

func (s *directTCPIPServer) serveConnection(connection net.Conn) {
	serverConnection, channels, requests, err := ssh.NewServerConn(connection, s.config)
	if err != nil {
		_ = connection.Close()
		return
	}
	s.handshakes.Add(1)
	s.mu.Lock()
	s.clients[serverConnection] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, serverConnection)
		s.mu.Unlock()
		_ = serverConnection.Close()
	}()
	go ssh.DiscardRequests(requests)
	serveDirectTCPIPChannels(channels)
}

func (s *directTCPIPServer) CloseClients() {
	s.mu.Lock()
	clients := make([]*ssh.ServerConn, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.Unlock()
	for _, client := range clients {
		_ = client.Close()
	}
}

func serveDirectTCPIPChannels(channels <-chan ssh.NewChannel) {
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "direct-tcpip" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "仅支持 direct-tcpip")
			continue
		}
		var request directTCPIPRequest
		if err := ssh.Unmarshal(channelRequest.ExtraData(), &request); err != nil {
			_ = channelRequest.Reject(ssh.ConnectionFailed, "目标参数无效")
			continue
		}
		destination := net.JoinHostPort(request.DestinationAddress, strconv.Itoa(int(request.DestinationPort)))
		upstream, err := net.DialTimeout("tcp", destination, 3*time.Second)
		if err != nil {
			_ = channelRequest.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			_ = upstream.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go func() {
			_, _ = io.Copy(upstream, channel)
			_ = upstream.Close()
		}()
		go func() {
			_, _ = io.Copy(channel, upstream)
			_ = channel.Close()
		}()
	}
}
