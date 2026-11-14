package openvpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	engine "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/diag"
	ovpnprofile "github.com/buengese/go-openvpn/profile"
)

type Config struct {
	Text, ProfileID, ProfileName, Username string
	Password                               []byte
	OTP                                    *OTPBroker
}

type Session struct {
	client        *engine.Client
	device        *memoryDevice
	diagMu        sync.RWMutex
	lastDataError string
	probeHost     string
}

// parseProfile 保留 CA、备用服务器、压缩及密码套件；OTP 由宿主提供，不传给指令解析器。
func parseProfile(text string) (*ovpnprofile.Profile, string, error) {
	if err := Validate(text); err != nil {
		return nil, "", err
	}
	var normalized strings.Builder
	prompt := ""
	for _, line := range strings.Split(text, "\n") {
		line = stripInlineComment(line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "<connection>" || trimmed == "</connection>" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && fields[0] == "static-challenge" {
			start := strings.TrimSpace(strings.TrimPrefix(trimmed, "static-challenge"))
			if strings.HasPrefix(start, `"`) {
				end := 1
				for end < len(start) {
					if start[end] == '\\' {
						end += 2
						continue
					}
					if start[end] == '"' {
						break
					}
					end++
				}
				if end >= len(start) {
					return nil, "", fmt.Errorf("验证码提示的引号未闭合")
				}
				value, err := strconv.Unquote(start[:end+1])
				if err != nil {
					return nil, "", fmt.Errorf("验证码提示格式无效")
				}
				prompt = value
			} else if len(fields) >= 3 {
				prompt = strings.Trim(fields[1], "'")
			} else {
				return nil, "", fmt.Errorf("验证码提示格式无效")
			}
			if prompt == "" {
				return nil, "", fmt.Errorf("验证码提示不能为空")
			}
			continue
		}
		normalized.WriteString(line + "\n")
	}
	profile, err := ovpnprofile.ParseString(normalized.String())
	if err != nil {
		return nil, "", fmt.Errorf("OpenVPN 配置解析失败，请检查服务器、协议及证书")
	}
	return profile, prompt, nil
}

// stripInlineComment 保留引号内的提示文字，移除学校 remote 行末的显示用途注释。
func stripInlineComment(line string) string {
	var quote byte
	for index := 0; index < len(line); index++ {
		value := line[index]
		if value == '\\' {
			index++
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '"' || value == '\'' {
			quote = value
			continue
		}
		if (value == '#' || value == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			return line[:index]
		}
	}
	return line
}

func Open(ctx context.Context, config Config) (*Session, error) {
	profile, prompt, err := parseProfile(config.Text)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(config.Username+string(config.Password), "\r\n\x00") {
		return nil, fmt.Errorf("账号或密码包含不支持的控制字符")
	}
	backend := &memoryBackend{}
	client := engine.New(profile)
	session := &Session{client: client}
	for _, remote := range profile.Remotes {
		if net.ParseIP(remote.Host) == nil && len(remote.Host) <= 253 {
			session.probeHost = remote.Host
			break
		}
	}
	client.EventFn = func(event engine.Event) {
		if strings.HasPrefix(event.Message, "vpn: data packet dropped: ") {
			session.diagMu.Lock()
			session.lastDataError = strings.TrimPrefix(event.Message, "vpn: data packet dropped: ")
			session.diagMu.Unlock()
		}
	}
	client.Device = backend
	client.CredentialsFn = func(authContext context.Context) (engine.Credentials, error) {
		password := string(config.Password)
		if prompt != "" {
			if config.OTP == nil {
				return engine.Credentials{}, fmt.Errorf("当前环境无法输入验证码")
			}
			code, err := config.OTP.Request(authContext, Challenge{ProfileID: config.ProfileID, ProfileName: config.ProfileName, Username: config.Username, Prompt: prompt})
			if err != nil {
				return engine.Credentials{}, err
			}
			password = packStaticChallenge(config.Password, code)
		}
		return engine.Credentials{Username: config.Username, Password: password}, nil
	}
	// 协议诊断可能含服务端消息，使用固定的中文错误映射，禁止输出认证内容。
	if err := client.Connect(ctx); err != nil {
		_ = client.Disconnect()
		return nil, connectionError(ctx, err)
	}
	client.CredentialsFn = nil
	device, ok := client.TunnelDevice().(*memoryDevice)
	if !ok || device == nil {
		_ = client.Disconnect()
		return nil, fmt.Errorf("OpenVPN 用户态网络初始化失败")
	}
	session.device = device
	return session, nil
}

func packStaticChallenge(password []byte, code string) string {
	return "SCRV1:" + base64.StdEncoding.EncodeToString(password) + ":" + base64.StdEncoding.EncodeToString([]byte(code))
}

func connectionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("OpenVPN 连接已取消或超时，请重试并输入当前验证码")
	}
	var diagnostic *diag.Error
	if errors.As(err, &diagnostic) {
		switch diagnostic.Class {
		case diag.ClassAuth:
			return fmt.Errorf("OpenVPN 认证失败或验证码输入已取消，请核对VPN 账号、密码和当前验证码")
		case diag.ClassTLS:
			return fmt.Errorf("OpenVPN 服务器证书或 TLS 验证失败，请重新获取 VPN 服务提供方的配置")
		case diag.ClassConfig, diag.ClassUnsupported:
			return fmt.Errorf("OpenVPN 配置包含当前进程内协议不支持的参数")
		}
	}
	return fmt.Errorf("OpenVPN 连接失败，请检查网络、VPN 服务器状态和配置兼容性")
}

func (s *Session) Done() <-chan struct{} { return s.client.Done() }
func (s *Session) IPAddress() string     { return s.device.address.String() }

// Diagnostics 只公开协议参数与数据计数，禁止携带密码、验证码、密钥及原始推送内容。
func (s *Session) Diagnostics() map[string]any {
	report := s.client.Report()
	s.diagMu.RLock()
	lastDataError := s.lastDataError
	s.diagMu.RUnlock()
	return map[string]any{
		"client_ip": s.IPAddress(), "peer_id": report.Negotiated.PeerID,
		"cipher": report.Negotiated.Cipher, "compression": report.Negotiated.Compression,
		"key_derivation": report.Negotiated.KeyDerivation, "wire_format": report.Negotiated.WireFormat,
		"packets_sent": report.Counters.PacketsSent, "packets_received": report.Counters.PacketsRecv,
		"bytes_sent": report.Counters.BytesSent, "bytes_received": report.Counters.BytesRecv,
		"decrypt_failures": report.Counters.DecryptFailures,
		"last_data_error":  lastDataError,
	}
}

// ProbeDNS 仅通过推送的 DNS 查询配置中的 VPN 主机名，以区分数据通道与目标端口故障。
// 不使用本机解析器，不记录查询结果，也不扩大可访问的 SSH 目标范围。
func (s *Session) ProbeDNS(ctx context.Context) string {
	if s.probeHost == "" || !s.device.hasDNS {
		return "not_available"
	}
	probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := s.device.network.LookupContextHost(probeContext, s.probeHost)
	if err == nil && len(addresses) > 0 {
		return "reply_received"
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return "reply_received"
	}
	return "no_reply"
}

func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case <-s.Done():
		return nil, net.ErrClosed
	default:
	}
	return s.device.network.DialContext(ctx, network, address)
}
func (s *Session) Close() error {
	err := s.client.Disconnect()
	_ = s.device.Close()
	return err
}
