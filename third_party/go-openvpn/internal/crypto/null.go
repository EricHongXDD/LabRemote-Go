// SPDX-License-Identifier: LGPL-2.1-or-later
// LabRemote 修改：2026-11-14，支持学校配置 cipher none 的认证数据通道。

package crypto

import (
	"crypto/hmac"
	"fmt"
)

// NullCipher 不加密载荷，但验证 HMAC；序列号与载荷一起参与认证。
// 协议依据：OpenVPN 2.6 src/openvpn/crypto.c openvpn_encrypt_v1 的无加密分支。
// 此处仅使用协议字节布局，自行实现 Go 认证逻辑。
type NullCipher struct {
	digest Digest
	key    []byte
}

func NewNullCipher(digest Digest, key []byte) (*NullCipher, error) {
	if digest.Hash() == nil || len(key) < digest.Size() {
		return nil, fmt.Errorf("无效的 HMAC 密钥或摘要")
	}
	return &NullCipher{digest: digest, key: append([]byte(nil), key[:digest.Size()]...)}, nil
}

func (c *NullCipher) Seal(_ uint32, plain, _ []byte) []byte {
	mac := hmac.New(c.digest.Hash(), c.key)
	_, _ = mac.Write(plain)
	return append(mac.Sum(nil), plain...)
}

func (c *NullCipher) Open(_ uint32, data, _ []byte) ([]byte, error) {
	size := c.digest.Size()
	if len(data) < size+4 {
		return nil, fmt.Errorf("认证数据包过短")
	}
	mac := hmac.New(c.digest.Hash(), c.key)
	_, _ = mac.Write(data[size:])
	if !hmac.Equal(data[:size], mac.Sum(nil)) {
		return nil, fmt.Errorf("数据包 HMAC 验证失败")
	}
	return append([]byte(nil), data[size:]...), nil
}

func (c *NullCipher) IsAEAD() bool  { return false }
func (c *NullCipher) Overhead() int { return c.digest.Size() + 4 }
