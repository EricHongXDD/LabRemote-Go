// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// device.go — 设备标识（device_id）的生成与持久化。
//
// 为什么需要它：数据面的隧道认证 JSON 里 `deviceId` 是必填项，网关据此
// 把连接归到某台设备。geektrust §2.2 记录了两条硬约束：
//
//   - 格式是 **32 位大写十六进制**
//   - **首次登录后必须持久化并保持不变**，更换后服务器会视为新设备
//
// 也就是说这个值不能每次运行重算。它既不敏感（不是密钥，只是标识），
// 也不能丢（丢了就变成"新设备"，可能触发重新授信或二次验证）。
//
// 存放位置：与 setting.xml 同目录下的 atrust_device_id 文件。
// 不写进 setting.xml 的原因是那份配置由 VPNService 的锁保护，而
// device_id 属于 aTrust 后端的内部状态，不该出现在用户可见的配置里。

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// deviceIDFile 是设备标识的落盘文件名。
const deviceIDFile = "atrust_device_id"

// EnsureDeviceID 返回本机的 aTrust 设备标识，必要时生成并持久化。
//
// dir 为存放目录（通常是 setting.xml 所在目录）。dir 为空时只生成
// 内存中的值，不持久化——这会让每次运行都是"新设备"，仅适合测试。
func EnsureDeviceID(dir string) (string, error) {
	if dir == "" {
		return newDeviceID()
	}

	path := filepath.Join(dir, deviceIDFile)
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); isValidDeviceID(id) {
			return id, nil
		}
		// 文件存在但内容不合法：不覆盖它，报错让人看一眼。
		// 静默重写会掩盖"另一个程序在写这个文件"这类问题。
		return "", fmt.Errorf("aTrust: %s 内容不是 32 位大写十六进制设备标识", path)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("aTrust: 读取 %s 失败: %w", path, err)
	}

	id, err := newDeviceID()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("aTrust: 创建目录 %s 失败: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("aTrust: 写入 %s 失败: %w", path, err)
	}
	return id, nil
}

// newDeviceID 生成一个 32 位大写十六进制的随机标识。
func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("aTrust: 生成设备标识失败: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(b[:])), nil
}

// isValidDeviceID 检查是否为 32 位十六进制（大小写都接受，读取时统一大写）。
func isValidDeviceID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// SetDeviceID 手动注入设备标识。
//
// 供测试与"从外部恢复会话"两种场景使用。传入空串等价于清除。
func (c *Client) SetDeviceID(id string) {
	c.mu.Lock()
	c.deviceID = strings.ToUpper(strings.TrimSpace(id))
	c.mu.Unlock()
}

// DeviceID 返回当前设备标识（未设置时为空）。
func (c *Client) DeviceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.deviceID
}

// SetUsername 记录登录用户名。
//
// 隧道认证 JSON 的 userName 字段用它。Authenticate 会自动设置；
// 显式提供这个方法是为了让上层在恢复会话时也能补上。
func (c *Client) SetUsername(name string) {
	c.mu.Lock()
	c.username = name
	c.mu.Unlock()
}

// Username 返回当前登录用户名。
func (c *Client) Username() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.username
}
