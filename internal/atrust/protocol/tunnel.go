// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// tunnel.go — aTrust 数据面：TCP 流式通道。
//
// 控制面（client.go / endpoints.go）只负责登录与拿资源树。真正让内网可达的
// 是这里：对目标应用所属的网关 `<host>:441` 建一条 TLS 连接，在上面跑
// aTrust 自己的二进制帧协议，代理一条 TCP 流。
//
// 规范来源与取舍
// ==============
//
// 两份独立实现（geektrust §5.5、libreatrust transport.rs）都走同一条
// **TCP 流式通道**，帧格式一致，但在两个细节上有分歧：
//
//  1. 认证 JSON 之后是否先发目标地址帧
//     libreatrust: 先 send_tcp_init，紧接着 send_tcp_dest，两者都在
//                  等待连接结果之前写完（"认证与目标地址必须合并写入"）。
//     geektrust:   §5.5 也说是"同一次写入"，与 libreatrust 一致。
//     ⇒ 这里按两者一致的做法：先认证帧、再地址帧，然后等 0x05 状态。
//
//  2. 初始化后直接读取完整 SOCKS 风格连接结果，连接成功前不发送空数据帧。
//     否则部分网关会接受初始化后关闭第一段应用数据。
//
// 帧格式总结
// ==========
//
//	0x05 <cmd> ...              隧道控制帧（版本字节固定 0x05）
//	0x01 <0x00|0x01> <BE16>..   TCP 数据帧：0x00=载荷，0x01=控制
//	0x53 0x00 <BE16> <json>     S 帧（认证后的状态 JSON）
//
// 建立时序：
//
//	C→S: 05 01 81 | 53 03 <BE16 len> <authJSON> | 05 01 01 <ATYP> <addr> <BE16 port>
//	S→C: 05 81 | 53 00 <BE16 len> <{"code":0,"message":"OK"}> | 05 00
//	之后: 01 00 <BE16 len> <payload> 双向
//
// ⚠ 本文件只实现 TCP。UDP / ICMP 走 L3 数据面（0x14/0x94 IPv4 小包），
// 那是另一套协议，且需要用户态 TCP/IP 栈，不在本文件范围内。

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 隧道帧常量。数值来自 geektrust §5.2 与 libreatrust transport.rs 的交叉比对。
const (
	tunnelVersion = 0x05

	cmdTunnelAuth    = 0x01 // 隧道认证（方法协商 0x81 / 0xD0）
	cmdTunnelStatus  = 0x00 // 隧道状态响应
	cmdTCPData       = 0x01 // TCP 数据帧（首字节）
	cmdTCPDataMarker = 0x00 // TCP 数据帧（次字节 0x00 = 载荷）
	cmdTCPControl    = 0x01 // TCP 数据帧（次字节 0x01 = 控制）
	cmdSFrame        = 0x53 // S 帧

	// authMethodStreamTCP 是流式 TCP 通道的认证方法字节（0x81）。
	//
	// geektrust §5.5 写的是 "05 01 81"，libreatrust 的 send_tcp_init 也是
	// 0x05 0x01 0x81。两处一致。
	authMethodStreamTCP = 0x81

	// sFrameAuthType 是认证 JSON 的 S 帧子类型（0x03）。
	sFrameAuthType = 0x03

	// tunnelDialTimeout 限制到网关 441 的 TLS 握手。
	tunnelDialTimeout = 15 * time.Second

	// tunnelConnectStatusTimeout 限制"等到连接结果"这一步。
	//
	// 网关要替我们去连目标主机，这一步会等真实的 TCP 握手，因此不能太短。
	tunnelConnectStatusTimeout = 30 * time.Second
)

// ErrNotManaged 表示目标不在资源树的任何路由规则内。
//
// 这不是网络错误：客户端连本地监听端口时就已经决定了目标，网关侧不该
// 替它做路由决策。出现它说明本地路由表与资源树脱节了。
var ErrNotManaged = errors.New("atrust: 目标不在资源路由表内")

// TCPConn 是一条经由 aTrust 隧道代理的 TCP 连接。
//
// 它实现了 net.Conn，因此可以直接交给 io.Copy 与任何基于 net.Conn 的
// 上层（HTTP 客户端、SOCKS5 转发器等）。
type TCPConn struct {
	conn *tls.Conn

	// readMu 保护 conn 的读，写由 writeMu 保护。
	// TLS 连接本身允许一读一写并发，但不允许多个并发读或多个并发写。
	readMu  sync.Mutex
	writeMu sync.Mutex

	// readBuf 缓存已从隧道解出但尚未交给调用方的应用字节。
	//
	// 一个隧道帧可能含多个应用数据块，且帧边界与应用写入边界无关，
	// 所以必须缓存而不是"一次 Read 对应一次帧读"。
	readBuf []byte

	// closed 表示已发送关闭帧（01 01 00 00）。
	closed    bool
	closeOnce sync.Once

	localAddr  net.Addr
	remoteAddr net.Addr
}

// DialTCP 通过 aTrust 隧道连接目标 host:port。
//
// 调用方通常传入资源的真实地址（资源树里的 addressList 条目）。
// 若 host 是域名，帧里按 ATYP=3（域名）发送，由网关侧解析；这与
// geektrust §4.2 的"域名规则由网关核对"是一致的。
//
// 只使用资源树里明确命中的规则及所属线路，未命中时返回 ErrNotManaged。
func (c *Client) DialTCP(ctx context.Context, host string, port int) (*TCPConn, error) {
	mat, err := c.sessionMaterial()
	if err != nil {
		return nil, err
	}

	entry, node := c.resolveTarget(host, port)
	if node == "" {
		return nil, fmt.Errorf("%w: %s:%d（也没有可用的数据面线路）", ErrNotManaged, host, port)
	}
	if entry.AppID != "" {
		mat.AppID = entry.AppID
	}
	c.logf("aTrust 数据面: %s:%d → 规则 %s，线路 %s", host, port, entry.String(), node)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostOnly(node)}
	if c.gatewayTLS != nil {
		tlsConfig = c.gatewayTLS(node)
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: tunnelDialTimeout}, Config: tlsConfig}
	raw, err := d.DialContext(ctx, "tcp", node)
	if err != nil {
		return nil, fmt.Errorf("atrust: 连接数据面线路 %s 失败: %w", node, err)
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopCancellation()

	conn := &TCPConn{
		conn:       raw.(*tls.Conn),
		localAddr:  raw.LocalAddr(),
		remoteAddr: raw.RemoteAddr(),
	}

	// 建立阶段整体设一个截止时间，避免卡在半开的网关上。
	_ = conn.conn.SetDeadline(time.Now().Add(tunnelConnectStatusTimeout))
	if err := conn.handshakeStream(mat, host, port, mat.AppID); err != nil {
		_ = conn.conn.Close()
		return nil, err
	}
	// 建立完成后清掉截止时间：后续读写由调用方自己的超时控制。
	_ = conn.conn.SetDeadline(time.Time{})

	return conn, nil
}

// resolveTarget 查路由表并选出线路。
//
// 未命中时不使用其他资源或默认线路代替授权。
func (c *Client) resolveTarget(host string, port int) (routeEntry, string) {
	c.mu.RLock()
	idx := c.resources
	c.mu.RUnlock()

	if idx == nil {
		return routeEntry{}, ""
	}
	if e, ok := idx.lookup(host, port); ok {
		return e, idx.nodeFor(e)
	}
	// 未授权目标禁止回退默认线路，更不能系统直连。
	return routeEntry{}, ""
}

// handshakeStream 执行 §5.5 的三段式建立。
func (c *TCPConn) handshakeStream(mat *sessionMaterial, host string, port int, appID string) error {
	authJSON := buildStreamAuthJSON(mat, host, port, appID)

	// ★ 认证帧与目标地址帧必须在**同一次写入**中发出。
	//
	// geektrust §5.5 与 libreatrust send_tcp_init/send_tcp_dest 都是这么做的。
	// 分成两次 Write 在部分网关上是可用的，但 TLS 记录边界会变，而网关
	// 侧的解析是按记录来的——合并写入是两者都验证过的形态。
	var buf []byte
	buf = append(buf, tunnelVersion, cmdTunnelAuth, authMethodStreamTCP, cmdSFrame, sFrameAuthType)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(authJSON)))
	buf = append(buf, authJSON...)
	buf = appendTarget(buf, host, port)

	if _, err := c.conn.Write(buf); err != nil {
		return fmt.Errorf("atrust: 发送隧道建立帧失败: %w", err)
	}

	// 读认证结果：先可能收到 05 81，再是 53 00 <len> <json>。
	if err := c.readAuthResult(); err != nil {
		return err
	}

	// 目标连接结果。
	return c.waitConnectStatus()
}

// readAuthResult 读取隧道认证响应。
//
// 两种形态都接受（libreatrust 的 wait_for_tcp_connect_status 同样如此）：
//
//	53 00 <BE16> <json>            —— 直接给 S 帧
//	05 81 53 00 <BE16> <json>      —— 先给 05 81 再给 S 帧
func (c *TCPConn) readAuthResult() error {
	for i := 0; i < 4; i++ {
		var hdr [2]byte
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return fmt.Errorf("atrust: 读取隧道认证响应失败: %w", err)
		}

		switch [2]byte{hdr[0], hdr[1]} {
		case [2]byte{cmdSFrame, 0x00}:
			payload, err := readBE16Payload(c.conn)
			if err != nil {
				return err
			}
			return checkAuthPayload(payload)

		case [2]byte{tunnelVersion, authMethodStreamTCP}:
			// 05 81 之后紧跟 53 00，继续循环即可。

		case [2]byte{tunnelVersion, cmdTunnelStatus}:
			// 个别网关会先给一个 05 00 状态帧，跳过。

		default:
			return fmt.Errorf("atrust: 隧道认证阶段收到意外帧 %02x %02x", hdr[0], hdr[1])
		}
	}
	return errors.New("atrust: 隧道认证响应层数过多（未收到 S 帧）")
}

// checkAuthPayload 检查认证 JSON 的 message 字段。
func checkAuthPayload(payload []byte) error {
	// 严格解析状态，不能让嵌套文本或前缀匹配把失败响应判成成功。
	var result struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &result) != nil {
		return errors.New("atrust: 隧道认证状态格式无效")
	}
	if result.Code != nil {
		if *result.Code == 0 {
			return nil
		}
		return errors.New("atrust: 隧道认证被拒绝")
	}
	if result.Message == "OK" || result.Message == "Succeeded" {
		return nil
	}
	return errors.New("atrust: 隧道认证被拒绝")
}

// waitConnectStatus 读取目标连接结果。
//
// 成功响应必须完整消费绑定地址和端口，避免剩余字节污染 SSH 数据帧。
func (c *TCPConn) waitConnectStatus() error {
	for i := 0; i < 8; i++ {
		var hdr [2]byte
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return fmt.Errorf("atrust: 读取连接结果失败: %w", err)
		}

		if hdr[0] == tunnelVersion {
			// 05 <status>：这是连接结果，或一条控制状态。
			switch hdr[1] {
			case 0x00:
				return c.readBoundAddress()
			case 0x01:
				return errors.New("atrust: 隧道侧连接失败")
			case 0x02:
				return errors.New("atrust: 该连接不被允许")
			case 0x03:
				return errors.New("atrust: 网络不可达")
			case 0x04:
				return errors.New("atrust: 主机不可达")
			case 0x05:
				return errors.New("atrust: 连接被拒绝")
			case 0x06:
				return errors.New("atrust: 隧道 TTL 到期")
			case 0x07:
				return errors.New("atrust: 隧道不支持该命令")
			case 0x08:
				return errors.New("atrust: 不支持的地址类型")
			default:
				return fmt.Errorf("atrust: 隧道连接失败，状态 0x%02X", hdr[1])
			}
		}

		// 非 05 开头的：可能是 S 帧或数据帧提前到达，按通用帧消费。
		if err := c.consumeFrame(hdr); err != nil {
			return err
		}
	}
	return errors.New("atrust: 等待连接结果超时（未收到 05 状态帧）")
}

func (c *TCPConn) readBoundAddress() error {
	var header [2]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return fmt.Errorf("atrust: 读取连接绑定地址失败: %w", err)
	}
	// 部分网关 RSV 非零，仅按 ATYP 决定地址长度。
	length := 0
	switch header[1] {
	case 1:
		length = net.IPv4len
	case 4:
		length = net.IPv6len
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(c.conn, size[:]); err != nil {
			return err
		}
		length = int(size[0])
	default:
		return fmt.Errorf("atrust: 连接结果中的地址类型无效（%d）", header[1])
	}
	_, err := io.CopyN(io.Discard, c.conn, int64(length+2))
	return err
}

// consumeFrame 消费一个非 0x05 开头的隧道帧。
func (c *TCPConn) consumeFrame(hdr [2]byte) error {
	switch hdr {
	case [2]byte{cmdSFrame, 0x00}:
		payload, err := readBE16Payload(c.conn)
		if err != nil {
			return err
		}
		return checkAuthPayload(payload)

	case [2]byte{cmdTCPData, cmdTCPDataMarker}:
		payload, err := readBE16Payload(c.conn)
		if err != nil {
			return err
		}
		c.readBuf = append(c.readBuf, payload...)
		return nil

	case [2]byte{cmdTCPData, cmdTCPControl}:
		var tail [2]byte
		if _, err := io.ReadFull(c.conn, tail[:]); err != nil {
			return err
		}
		if tail == [2]byte{0x00, 0x00} || tail == [2]byte{0x30, 0x30} {
			return io.EOF
		}
		return nil

	default:
		// 未文档化的扩展头。libreatrust 的做法是消费掉继续，
		// 这里无法判断长度，只能报错——静默跳过会破坏后续帧对齐。
		return fmt.Errorf("atrust: 隧道中出现无法解析的帧 %02x %02x", hdr[0], hdr[1])
	}
}

// ---------- 数据读写 ----------

// Read 实现 net.Conn。
func (c *TCPConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return 0, err
		}
		if err := c.consumeFrame(hdr); err != nil {
			return 0, err
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write 实现 net.Conn：把应用字节封成 01 00 <BE16 len> <data>。
func (c *TCPConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0xFFFF {
			n = 0xFFFF
		}
		frame := make([]byte, 4+n)
		frame[0], frame[1] = cmdTCPData, cmdTCPDataMarker
		binary.BigEndian.PutUint16(frame[2:4], uint16(n))
		copy(frame[4:], p[:n])

		if _, err := c.conn.Write(frame); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close 发送关闭帧并关闭底层连接。
//
// 先发 `01 01 00 00` 告诉网关"本方向不再有数据"，再关 TLS 连接。
// 直接关 TLS 会让网关侧把连接判为异常中断。
func (c *TCPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// 先限制底层写入，让正在阻塞的发送及关闭帧都能及时结束。
		_ = c.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		c.writeMu.Lock()
		if !c.closed {
			c.closed = true
			_, _ = c.conn.Write([]byte{cmdTCPData, cmdTCPControl, 0x00, 0x00})
		}
		c.writeMu.Unlock()
		err = c.conn.Close()
	})
	return err
}

func (c *TCPConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *TCPConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *TCPConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *TCPConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *TCPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ---------- 帧辅助 ----------

// readBE16Payload 读取 <BE16 len> <payload>。
func readBE16Payload(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// appendTarget 追加目标地址帧：05 01 01 <ATYP> <addr> <BE16 port>。
//
// ATYP：1=IPv4，3=域名，4=IPv6。与 SOCKS5 的 ATYP 取值相同，
// libreatrust send_tcp_dest 也是这套编码。
func appendTarget(buf []byte, host string, port int) []byte {
	buf = append(buf, tunnelVersion, cmdTunnelAuth, cmdTCPControl)

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}

	return binary.BigEndian.AppendUint16(buf, uint16(port))
}

// ---------- 建立隧道所需的材料 ----------

// sessionMaterial 是隧道认证需要的全部会话信息。
type sessionMaterial struct {
	Sid          string
	DeviceID     string
	ConnectionID string
	Username     string
	AppID        string
	SignKeyHex   string
}

// buildStreamAuthJSON 构造 §5.5 的认证 JSON。
//
// 字段顺序在这里是**有意义的**：签名（若启用）覆盖的是序列化后的字节，
// 顺序变了签名就不对。libreatrust 用格式串固定顺序，这里用显式拼接
// 达到同样效果，而不是靠 struct 的字段声明顺序——后者在加字段时太容易错。
//
// 当前仅适配接受空 xRequestSig 的网关；要求额外签名时由网关拒绝连接。
func buildStreamAuthJSON(mat *sessionMaterial, host string, port int, appID string) string {
	procPath, _ := os.Executable()
	procName := filepath.Base(procPath)
	procHash := ""
	if executable, err := os.Open(procPath); err == nil {
		h := sha256.New()
		_, _ = io.Copy(h, executable)
		_ = executable.Close()
		procHash = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	}

	url := fmt.Sprintf("tcp:%s:%d", host, port)

	var b strings.Builder
	b.WriteString(`{"sid":"`)
	b.WriteString(jsonEscape(mat.Sid))
	b.WriteString(`","appId":"`)
	b.WriteString(jsonEscape(appID))
	b.WriteString(`","url":"`)
	b.WriteString(jsonEscape(url))
	b.WriteString(`","deviceId":"`)
	b.WriteString(jsonEscape(mat.DeviceID))
	b.WriteString(`","connectionId":"`)
	b.WriteString(jsonEscape(mat.ConnectionID))
	b.WriteString(`","procHash":"`)
	b.WriteString(procHash)
	b.WriteString(`","userName":"`)
	b.WriteString(jsonEscape(mat.Username))
	b.WriteString(`","lang":"zh-CN","destAddr":"`)
	b.WriteString(jsonEscape(fmt.Sprintf("%s:%d", host, port)))
	b.WriteString(`","env":{"application":{"runtime":{"process":{"name":"`)
	b.WriteString(jsonEscape(procName))
	b.WriteString(`","digital_signature":"UNKNOWN","platform":"Windows","fingerprint":"`)
	b.WriteString(procHash)
	b.WriteString(`","description":"UNKNOWN","path":"`)
	b.WriteString(jsonEscape(procPath))
	b.WriteString(`","version":"UNKNOWN","security_env":"normal"},"process_trusted":"UNKNOWN"}}},"xRequestSig":""}`)

	return b.String()
}

// nodeForResource 从资源树里挑出目标所属的 nodeGroupId 并解析成 host:port。
//
// 资源条目本身带 nodeGroupId；节点组地址来自 config.nodeGroupConf。
// 缺任一层都建不了隧道——这时返回空串，由调用方给出明确错误。
func (c *Client) dataNode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeAddr
}

// sessionMaterial 汇总隧道认证所需的会话材料。
func (c *Client) sessionMaterial() (*sessionMaterial, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.sidTicket == "" {
		return nil, ErrNoSession
	}
	mat := &sessionMaterial{
		Sid:      c.sidTicket,
		Username: c.username,
		DeviceID: c.deviceID,
	}
	if mat.DeviceID == "" {
		// deviceId 是网关侧的设备标识。没有它时用 guid 兜底会让网关把
		// 我们当成另一台设备，产生一条不必要的授信记录；不如直接报错。
		return nil, errors.New("atrust: 缺少 deviceId，无法建立数据面隧道")
	}
	mat.ConnectionID = fmt.Sprintf("%s-%d", upperMD5Hex(mat.DeviceID), time.Now().UnixMicro())
	mat.AppID = c.currentAppID
	mat.SignKeyHex = c.signKey
	return mat, nil
}

// ---------- 小工具 ----------

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func parsePort(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
