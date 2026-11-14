package openvpn

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const MaxConfigSize = 1024 * 1024

// Import 仅从压缩包读取配置，不解压到磁盘，也不执行其中的指令。
func Import(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("无法读取 OpenVPN 配置文件")
	}
	defer f.Close()
	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		info, err := f.Stat()
		if err != nil {
			return "", err
		}
		archive, err := zip.NewReader(f, info.Size())
		if err != nil {
			return "", fmt.Errorf("无效的 ZIP 配置包")
		}
		var selected *zip.File
		for _, entry := range archive.File {
			if !entry.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(entry.Name), ".ovpn") {
				if selected != nil {
					return "", fmt.Errorf("配置包包含多个 .ovpn，请解压后选择一个")
				}
				selected = entry
			}
		}
		if selected == nil {
			return "", fmt.Errorf("配置包内未找到 .ovpn 文件")
		}
		r, err := selected.Open()
		if err != nil {
			return "", fmt.Errorf("无法读取 ZIP 中的配置")
		}
		defer r.Close()
		reader = r
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigSize+1))
	if err != nil {
		return "", fmt.Errorf("读取 OpenVPN 配置失败")
	}
	config := strings.TrimPrefix(string(data), "\ufeff")
	if err := Validate(config); err != nil {
		return "", err
	}
	return config, nil
}

// Validate 限定为内嵌 CA、账号密码认证配置，拒绝脚本、外部文件及管理端口覆盖。
func Validate(config string) error {
	if len(config) == 0 || len(config) > MaxConfigSize || !utf8.ValidString(config) || strings.ContainsRune(config, 0) {
		return fmt.Errorf("OpenVPN 配置必须为不超过 1 MiB 的 UTF-8 文本")
	}
	allowed := strings.Fields("client dev proto remote remote-random remote-random-hostname nobind resolv-retry connect-retry connect-retry-max connect-timeout server-poll-timeout reneg-sec auth-user-pass remote-cert-tls verify-x509-name verb mute auth cipher data-ciphers data-ciphers-fallback comp-lzo compress allow-compression sndbuf rcvbuf mssfix tun-mtu persist-key persist-tun explicit-exit-notify static-challenge tls-version-min tls-version-max tls-cipher tls-ciphersuites auth-nocache key-direction")
	options := make(map[string]bool)
	for _, name := range allowed {
		options[name] = true
	}
	scanner := bufio.NewScanner(strings.NewReader(config))
	scanner.Buffer(make([]byte, 4096), MaxConfigSize)
	insideCA, insideConnection, hasCA, hasRemote, hasClient, hasAuth, hasVerify, hasTun := false, false, false, false, false, false, false, false
	var ca bytes.Buffer
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if insideCA {
			if line == "</ca>" {
				insideCA = false
				remaining := bytes.TrimSpace(ca.Bytes())
				if len(remaining) == 0 {
					return fmt.Errorf("内嵌 CA 证书不能为空")
				}
				for len(remaining) > 0 {
					if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
						return fmt.Errorf("CA 区块只能包含证书")
					}
					block, rest := pem.Decode(remaining)
					if block == nil || block.Type != "CERTIFICATE" {
						return fmt.Errorf("内嵌 CA 证书无效")
					}
					if _, err := x509.ParseCertificate(block.Bytes); err != nil {
						return fmt.Errorf("内嵌 CA 证书无效")
					}
					remaining = bytes.TrimSpace(rest)
				}
				hasCA = true
			} else {
				ca.WriteString(line + "\n")
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch line {
		case "<ca>":
			if hasCA || insideConnection {
				return fmt.Errorf("CA 区块位置无效或重复")
			}
			insideCA = true
			continue
		case "<connection>":
			if insideConnection {
				return fmt.Errorf("connection 区块不能嵌套")
			}
			insideConnection = true
			continue
		case "</connection>":
			if !insideConnection {
				return fmt.Errorf("connection 区块不匹配")
			}
			insideConnection = false
			continue
		}
		fields := strings.Fields(line)
		name := fields[0]
		if insideConnection && name != "remote" {
			return fmt.Errorf("connection 区块目前仅支持备用 remote 服务器列表")
		}
		if name == "setenv" && len(fields) == 3 && fields[1] == "CLIENT_CERT" && fields[2] == "0" {
			continue
		}
		if !options[name] {
			return fmt.Errorf("不支持 OpenVPN 指令 %s；请使用内嵌 CA 的账号密码配置，移除脚本及外部文件引用", name)
		}
		if name == "auth-user-pass" {
			if len(fields) > 1 && !strings.HasPrefix(fields[1], "#") && !strings.HasPrefix(fields[1], ";") {
				return fmt.Errorf("请移除 auth-user-pass 后的凭据文件，改在表单输入账号密码")
			}
			hasAuth = true
		}
		if name == "dev" {
			if len(fields) != 2 || fields[1] != "tun" {
				return fmt.Errorf("目前仅支持 dev tun 配置")
			}
			hasTun = true
		}
		if name == "remote" {
			if len(fields) < 2 {
				return fmt.Errorf("remote 缺少服务器地址")
			}
			hasRemote = true
		}
		if name == "client" {
			hasClient = true
		}
		if name == "remote-cert-tls" && len(fields) == 2 && fields[1] == "server" {
			hasVerify = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("配置行过长")
	}
	if insideCA || insideConnection || !hasCA || !hasRemote || !hasClient || !hasAuth || !hasVerify || !hasTun {
		return fmt.Errorf("配置需包含 client、dev tun、remote、auth-user-pass、remote-cert-tls server 及完整内嵌 CA")
	}
	return nil
}
