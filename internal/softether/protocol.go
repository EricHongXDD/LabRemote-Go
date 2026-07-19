package softether

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort       = 992
	keepAliveMagic    = uint32(0xffffffff)
	maxKeepAliveSize  = 512
	maxEthernetFrame  = 64 * 1024
	softEtherAuthType = 1
)

const watermarkBase64 = "R0lGODlhyAAzAPIAADY3NHloVICAgK9/W7OondXV1P///wAAACwAAAAAyAAzAAAD/gga3DQKBEFrZTFPEYD5YCiOZGmeaKqubOuaS+MMDCVvVqfp0uv/wKBwyIrcLJzGBccxZiQEonRKrU4FsQ1hyyXUuEkb5hmxms/o9AcrEXQJhXj8DW6Qn+oCgRI17ylqgSwECm5ccoh6em9NdxklcRZxLwWSBpWAIkgWfZgCmnyCBhYjfwIFa0hwIxV9H5ioIX+HibWLfHs8jiOem64rrSCmrJsUscMhFbGBniKersWZIJavxqBwtrZbAxwWjmUhvZvLKp7LweHRp6lu6daCzcnK1dGuvct/rLTZczQ3dt88yJoHQk44TKsK+hIX6lIFEgzbNdPzztkschO3QCLo/rBhx0/sQH6U9lATNoOoann5d+MbKGkbVQkbZ4oaqVLFUHFCgjHatFYVnXG8GfInST7vPE7bku1SvwH+AkSVsWugMnIKJXIc5RGZPF8zYXJ1k5IoQqN9cpogaIocOnM/4YSCVerkpbuJ3kxgMHUMnpfUjMYyO7Rk1nFGRX48Z7gwILgpgj1z55Meqj+R1olgmshpNqgbpP4jA1Htx8SHGbejzBMtZdWxIkreuvahV3oLs5Y9la8uSrwquSVhCRAcJFN9vKIz4BVyWMWvrYqEXBPx7RPmaFc/hbX3WMOyOqdUuYeGmL2jjdfORNTxdNpEhQYlfFTsV+gmGP4quv65/ubNiABXC1T+IDEaDwEUlNBhaZUUDzuuXDcWVs+9FKFhEg6mFHaIvUShPPYEdpB45IEmgHAPEKfEYZUtxlxFzokoGzQcxejRZK+s4hwK4uznYkzktAVRgJME549wAWyhYg3+dfjBdj1VVF0n0eAjE2Q7bmfNjiggUVpQ8kWJ3yu1eCYHFwSK5kZfLB2E3CS8YNYdeB8lpOV/dV5mGJdz8AGnhCeIWKEJ3sUFCT+IoHkkVA+AxmYHokQq6aQjIjrHNg0M0CiBoLVE6aegonFSNnDoJVWanEblj0ChtupqEKOeSZ6Sp6bKqaev5qrrCqVOmVcdtW6K6hi7FmusPnEg/kgWNl0kwamwaepw7LTGJtlFDRyMCiyB0HYqLbXgvpqkIbkMR26ftdrqKLEliFTSmI3Vpwkx9iUzSkifgDSmCnRWoa8PbRAnQRtMeaEuX52qZ+8a0zC88L3u3uswV/M2TMK/Elu8b5cWm7GxClnIMJzI22ia6gIJK3BxxxWzknG+Gmc88Vf4wmwUxO6yJzO8OsMsL8TsjCXxu/1+ELISxJFbMlRGFLfyzA/PG3HEQIPyMMb6kpI1w1NDh1/XqXDdsM5iV232mE2LPDLS5KaKsF9Pyxx1zGVXvS/ZQzvs9cT5au1yyza/LLhifp8t+Ahph7H2P2uqC5rCfLf79+Bj/scnNd0Y02021HJTHvnUHdsc+OgkLLBEDiyZ3m2akO8cesueux416XnLnTnp8I6te9iGUw3Iv6BzboASOZwncgc6tO12617DRPhN8e4N2M169/3Q7xrj/RL1YAe9s8+i4525AaafbnwNGOhgLbTsTh53uIF8nAbxF9hgbmgDL6BoVCpL/j78apAfGspXv9CYKwn5A4AhbtU6ADowDQS0Hw6O4BcjSPARZyDc9971P/l5KVICfGAacDe7tcDufSGUQgpF6LHYuW5r4BOaDFmWtZzZUGy+O0rnWCgKEiYGeGHrWeR++Lnd4ayIZasXDwMYMw3GzocUq5gN2TPFwNmtVXA7XOIIoSe7vAVvc7bTnBRhJzrAaRGEl3OiF4O4O6oN8YtQHOIVz9jDNJYQhoOrIRm9N0MOzk6H46NjuFYoyEKCsGiGTKQiF8nIRjrykZCMpCR1lQAAOw=="

type Config struct {
	Server         string
	Port           uint16
	Hub            string
	Username       string
	Password       []byte
	CertificatePin string
}

type CertificateError struct {
	Kind        string
	Address     string
	Fingerprint string
	Expected    string
}

func (e *CertificateError) Error() string {
	if e.Kind == "changed" {
		return "SoftEther 服务器证书指纹已变化"
	}
	return "SoftEther 服务器证书尚未确认"
}

type ProtocolError struct {
	Code uint32
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("SoftEther 服务器返回错误码 %d", e.Code)
}

type Session struct {
	raw      net.Conn
	secure   *tls.Conn
	reader   *bufio.Reader
	frames   chan []byte
	outbound chan []byte
	done     chan struct{}
	stopOnce sync.Once
	errMu    sync.RWMutex
	err      error
}

func Open(ctx context.Context, config Config) (*Session, error) {
	if config.Port == 0 {
		config.Port = defaultPort
	}
	hub := strings.TrimSpace(config.Hub)
	if hub == "" {
		hubs, err := EnumerateHubs(ctx, config)
		if err != nil {
			return nil, err
		}
		if len(hubs) != 1 {
			return nil, fmt.Errorf("服务器公开了 %d 个 Virtual Hub，请在连接配置中明确指定", len(hubs))
		}
		hub = hubs[0]
	}
	stream, err := openStream(ctx, config)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = stream.secure.Close()
		}
	}()
	randomValue, err := exchangeSignature(stream)
	if err != nil {
		return nil, err
	}
	welcome, err := login(stream, config, hub, randomValue)
	if err != nil {
		return nil, err
	}
	if welcome.getBool("use_encrypt") == false || welcome.getBool("use_compress") || welcome.getBool("half_connection") || welcome.getBool("qos") {
		return nil, errors.New("服务器协商了当前隔离传输不支持的会话模式")
	}
	if _, err := stream.raw.Write([]byte{0, 1, 2, 3, 4}); err != nil {
		return nil, err
	}
	_ = stream.raw.SetDeadline(time.Time{})
	session := &Session{
		raw: stream.raw, secure: stream.secure, reader: stream.reader,
		frames: make(chan []byte, 256), outbound: make(chan []byte, 256), done: make(chan struct{}),
	}
	keep = true
	go session.readLoop()
	go session.writeLoop()
	return session, nil
}

func EnumerateHubs(ctx context.Context, config Config) ([]string, error) {
	if config.Port == 0 {
		config.Port = defaultPort
	}
	stream, err := openStream(ctx, config)
	if err != nil {
		return nil, err
	}
	defer stream.secure.Close()
	if _, err := exchangeSignature(stream); err != nil {
		return nil, err
	}
	request := &pack{}
	request.addString("method", "enum_hub")
	addClientVersion(request)
	response, err := exchangePack(stream, request)
	if err != nil {
		return nil, err
	}
	if code := response.getInt("error"); code != 0 {
		return nil, &ProtocolError{Code: code}
	}
	count := int(response.getInt("NumHub"))
	if count > response.stringCount("HubName") {
		count = response.stringCount("HubName")
	}
	hubs := make([]string, 0, count)
	for index := 0; index < count; index++ {
		if value := strings.TrimSpace(response.getStringAt("HubName", index)); value != "" {
			hubs = append(hubs, value)
		}
	}
	return hubs, nil
}

type protocolStream struct {
	raw    net.Conn
	secure *tls.Conn
	reader *bufio.Reader
	host   string
}

func openStream(ctx context.Context, config Config) (*protocolStream, error) {
	address := net.JoinHostPort(strings.Trim(config.Server, "[]"), strconv.Itoa(int(config.Port)))
	raw, err := (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	tlsConfig := &tls.Config{
		ServerName:         strings.Trim(config.Server, "[]"),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("SoftEther 服务器未提供证书")
			}
			certificate := state.PeerCertificates[0]
			if err := verifyCertificateName(certificate, strings.Trim(config.Server, "[]")); err != nil {
				return fmt.Errorf("SoftEther 证书主机名不匹配: %w", err)
			}
			digest := sha256.Sum256(certificate.Raw)
			fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])
			if config.CertificatePin == "" {
				return &CertificateError{Kind: "unknown", Address: address, Fingerprint: fingerprint}
			}
			if config.CertificatePin != fingerprint {
				return &CertificateError{Kind: "changed", Address: address, Fingerprint: fingerprint, Expected: config.CertificatePin}
			}
			return nil
		},
	}
	secure := tls.Client(raw, tlsConfig)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &protocolStream{raw: raw, secure: secure, reader: bufio.NewReader(secure), host: address}, nil
}

func verifyCertificateName(certificate *x509.Certificate, hostname string) error {
	err := certificate.VerifyHostname(hostname)
	if err == nil {
		return nil
	}
	if len(certificate.DNSNames) == 0 && net.ParseIP(hostname) == nil && strings.EqualFold(strings.TrimSpace(certificate.Subject.CommonName), hostname) {
		return nil
	}
	return err
}

func exchangeSignature(stream *protocolStream) ([20]byte, error) {
	var empty [20]byte
	watermark, err := base64.StdEncoding.DecodeString(watermarkBase64)
	if err != nil {
		return empty, err
	}
	paddingSize, err := randomSize(2000)
	if err != nil {
		return empty, err
	}
	body := make([]byte, len(watermark)+paddingSize)
	copy(body, watermark)
	if _, err := rand.Read(body[len(watermark):]); err != nil {
		return empty, err
	}
	request, err := sendHTTP(stream, "/vpnsvc/connect.cgi", "image/jpeg", body)
	if err != nil {
		return empty, err
	}
	response, err := receiveHTTPPack(stream, request)
	if err != nil {
		return empty, err
	}
	if code := response.getInt("error"); code != 0 {
		return empty, &ProtocolError{Code: code}
	}
	randomValue := response.getData("random")
	if len(randomValue) != len(empty) || response.getString("hello") == "" {
		return empty, errors.New("SoftEther Hello 响应无效")
	}
	copy(empty[:], randomValue)
	return empty, nil
}

func login(stream *protocolStream, config Config, hub string, challenge [20]byte) (*pack, error) {
	passwordInput := make([]byte, 0, len(config.Password)+len(config.Username))
	passwordInput = append(passwordInput, config.Password...)
	passwordInput = append(passwordInput, strings.ToUpper(config.Username)...)
	hashedPassword := sha0(passwordInput)
	clear(passwordInput)
	secureInput := make([]byte, 0, 40)
	secureInput = append(secureInput, hashedPassword[:]...)
	secureInput = append(secureInput, challenge[:]...)
	securePassword := sha0(secureInput)
	clear(secureInput)

	request := &pack{}
	request.addString("method", "login")
	request.addString("hubname", hub)
	request.addString("username", config.Username)
	request.addInt("authtype", softEtherAuthType)
	request.addData("secure_password", securePassword[:])
	addClientVersion(request)
	request.addInt("protocol", 0)
	request.addString("hello", "LabRemote Isolated Transport")
	request.addInt("version", 1000)
	request.addInt("build", 1000)
	request.addInt("client_id", 123)
	request.addInt("max_connection", 1)
	request.addBool("use_encrypt", true)
	request.addBool("use_compress", false)
	request.addBool("half_connection", false)
	request.addBool("require_bridge_routing_mode", false)
	request.addBool("require_monitor_mode", false)
	request.addBool("qos", false)
	request.addBool("support_bulk_on_rudp", true)
	request.addBool("support_hmac_on_bulk_of_rudp", true)
	request.addBool("support_udp_recovery", true)
	uniqueInput := make([]byte, 64)
	if _, err := rand.Read(uniqueInput); err != nil {
		return nil, err
	}
	unique := sha0(uniqueInput)
	clear(uniqueInput)
	request.addData("unique_id", unique[:])
	request.addInt("rudp_bulk_max_version", 2)
	request.addString("branded_ctos", "Branded_VPN")
	addNodeInfo(request, hub)

	response, err := exchangePack(stream, request)
	if err != nil {
		return nil, err
	}
	if code := response.getInt("error"); code != 0 {
		return nil, &ProtocolError{Code: code}
	}
	if branded := response.getString("branded_cfroms"); branded != "" && branded != "Branded_VPN" {
		return nil, errors.New("SoftEther 品牌握手校验失败")
	}
	if response.getString("session_name") == "" || len(response.getData("session_key")) != 20 {
		return nil, errors.New("SoftEther Welcome 响应无效")
	}
	return response, nil
}

func addClientVersion(value *pack) {
	value.addString("client_str", "LabRemote Isolated Transport")
	value.addInt("client_ver", 1000)
	value.addInt("client_build", 1000)
}

func addNodeInfo(value *pack, hub string) {
	for _, item := range []struct{ name, text string }{
		{"ClientProductName", "LabRemote"}, {"ServerProductName", "SoftEther VPN Server"},
		{"ClientOsName", "Windows"}, {"ClientOsVer", runtime.GOARCH}, {"ClientOsProductId", "LabRemote"},
		{"ClientHostname", "LabRemote"}, {"ServerHostname", ""}, {"ProxyHostname", ""}, {"HubName", hub},
	} {
		value.addString(item.name, item.text)
	}
	value.addData("UniqueId", make([]byte, 16))
	for _, name := range []string{"ClientProductVer", "ClientProductBuild", "ServerProductVer", "ServerProductBuild", "ClientPort", "ServerPort2", "ProxyPort"} {
		value.addInt(name, 0)
	}
	for _, name := range []string{"ClientIpAddress", "ServerIpAddress", "ProxyIpAddress"} {
		addIPv4(value, name, 0)
	}
	for _, name := range []string{"ClientIpAddress6", "ServerIpAddress6", "ProxyIpAddress6"} {
		value.addData(name, make([]byte, 16))
	}
	value.addBool("V_IsWindows", true)
	value.addBool("V_IsNT", true)
	value.addBool("V_IsServer", false)
	value.addBool("V_IsBeta", false)
	for _, name := range []string{"V_VerMajor", "V_VerMinor", "V_Build", "V_ServicePack"} {
		value.addInt(name, 0)
	}
	value.addString("V_Title", "windows/"+runtime.GOARCH)
}

func addIPv4(value *pack, name string, address uint32) {
	value.addBool(name+"@ipv6_bool", false)
	value.addData(name+"@ipv6_array", make([]byte, 16))
	value.addInt(name+"@ipv6_scope_id", 0)
	value.addInt(name, address)
}

func exchangePack(stream *protocolStream, value *pack) (*pack, error) {
	paddingSize, err := randomSize(1000)
	if err != nil {
		return nil, err
	}
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	value.addData("pencore", padding)
	body, err := value.marshal()
	if err != nil {
		return nil, err
	}
	request, err := sendHTTP(stream, "/vpnsvc/vpn.cgi", "application/octet-stream", body)
	if err != nil {
		return nil, err
	}
	return receiveHTTPPack(stream, request)
}

func sendHTTP(stream *protocolStream, path, contentType string, body []byte) (*http.Request, error) {
	request := &http.Request{
		Method: "POST", URL: &url.URL{Path: path}, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Host: stream.host, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
		Header: http.Header{"Content-Type": []string{contentType}, "Keep-Alive": []string{"timeout=15; max=19"}},
	}
	return request, request.Write(stream.secure)
}

func receiveHTTPPack(stream *protocolStream, request *http.Request) (*pack, error) {
	response, err := http.ReadResponse(stream.reader, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Proto != "HTTP/1.1" || response.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, errors.New("目标不是兼容的 SoftEther VPN Server")
	}
	if response.ContentLength <= 0 || response.ContentLength > maxPackValue {
		return nil, errors.New("SoftEther HTTP 响应长度无效")
	}
	body := make([]byte, response.ContentLength)
	if _, err := io.ReadFull(response.Body, body); err != nil {
		return nil, err
	}
	return unmarshalPack(body)
}

func randomSize(max uint16) (int, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	if max == 0 {
		return 0, nil
	}
	return int(binary.BigEndian.Uint16(value[:]) % max), nil
}

func (session *Session) Frames() <-chan []byte { return session.frames }
func (session *Session) Done() <-chan struct{} { return session.done }

func (session *Session) Err() error {
	session.errMu.RLock()
	defer session.errMu.RUnlock()
	return session.err
}

func (session *Session) Send(frame []byte) error {
	if len(frame) < 14 || len(frame) > maxEthernetFrame {
		return errors.New("以太网帧长度无效")
	}
	copyValue := append([]byte(nil), frame...)
	select {
	case session.outbound <- copyValue:
		return nil
	case <-session.done:
		return session.closedError()
	}
}

func (session *Session) Close() error {
	session.stop(net.ErrClosed)
	return nil
}

func (session *Session) readLoop() {
	for {
		var count uint32
		if err := binary.Read(session.reader, binary.BigEndian, &count); err != nil {
			session.stop(err)
			return
		}
		if count == keepAliveMagic {
			var size uint32
			if err := binary.Read(session.reader, binary.BigEndian, &size); err != nil {
				session.stop(err)
				return
			}
			if size > maxKeepAliveSize {
				session.stop(errors.New("SoftEther keepalive 长度无效"))
				return
			}
			if _, err := io.CopyN(io.Discard, session.reader, int64(size)); err != nil {
				session.stop(err)
				return
			}
			continue
		}
		if count > 4096 {
			session.stop(errors.New("SoftEther 数据块数量超限"))
			return
		}
		for index := uint32(0); index < count; index++ {
			var size uint32
			if err := binary.Read(session.reader, binary.BigEndian, &size); err != nil {
				session.stop(err)
				return
			}
			if size < 14 || size > maxEthernetFrame {
				session.stop(errors.New("SoftEther 数据帧长度无效"))
				return
			}
			frame := make([]byte, size)
			if _, err := io.ReadFull(session.reader, frame); err != nil {
				session.stop(err)
				return
			}
			select {
			case session.frames <- frame:
			case <-session.done:
				return
			}
		}
	}
}

func (session *Session) writeLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case frame := <-session.outbound:
			if err := writeFrameBatch(session.secure, frame); err != nil {
				session.stop(err)
				return
			}
		case <-ticker.C:
			if err := writeKeepAlive(session.secure); err != nil {
				session.stop(err)
				return
			}
		case <-session.done:
			return
		}
	}
}

func writeFrameBatch(writer io.Writer, frame []byte) error {
	if err := binary.Write(writer, binary.BigEndian, uint32(1)); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(frame))); err != nil {
		return err
	}
	_, err := writer.Write(frame)
	return err
}

func writeKeepAlive(writer io.Writer) error {
	size, err := randomSize(maxKeepAliveSize)
	if err != nil {
		return err
	}
	if size == 0 {
		size = 1
	}
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, keepAliveMagic); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(size)); err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func (session *Session) stop(reason error) {
	session.stopOnce.Do(func() {
		session.errMu.Lock()
		session.err = reason
		session.errMu.Unlock()
		close(session.done)
		_ = session.secure.Close()
	})
}

func (session *Session) closedError() error {
	if err := session.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}
