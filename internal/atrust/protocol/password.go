// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// password.go — 口令的 RSA 加密。
//
// 这是**唯一一个已由官方实现证实的算法**：mock 网关用与官方客户端相同的
// 参数解出明文，尾部 rand 与下发的 antiReplayRand 完全一致（§24.2）。
//
// 规则（缺一不可）：
//  1. 明文 = "<password>_<antiReplayRand>"，下划线是字面分隔符
//  2. PKCS#1 v1.5 填充
//  3. 每 245 字符切一块（这是 k-11，k=256 即 RSA-2048 时的最大明文长度）
//  4. 每块单独加密，块密文转**小写 hex**
//  5. 各块 hex **直接首尾拼接**，无分隔符
//
// 第 3 条的 245 是硬编码的常量而非按密钥长度计算——官方实现就是这么写的，
// 对 RSA-2048 等价于 k-11，但若网关下发非 2048 位密钥，行为可能不同。
// 保留这个常量以保持与官方实现逐字节一致。

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	// plainChunkSize 是每个 RSA 块承载的最大明文字节数。
	// 官方实现里的字面量，等于 RSA-2048 的 k-11。
	plainChunkSize = 245
)

// ErrInvalidPubKey 表示 authConfig 里的 pubKey/pubKeyExp 无法解析。
var ErrInvalidPubKey = errors.New("aTrust: 网关公钥无法解析")

// ParsePublicKey 从 hex 模数与十进制指数还原 RSA 公钥。
//
// 对应官方实现：r.setPublic(pubKey, parseInt(pubKeyExp, 10).toString(16))。
// 注意 pubKeyExp 是**十进制字符串**（"65537"），不是 hex——把它当 hex 解析
// 会得到 0x65537 而不是 0x10001，加密结果网关解不开。
func ParsePublicKey(modHex, expDec string) (*rsa.PublicKey, error) {
	modHex = strings.TrimSpace(modHex)
	expDec = strings.TrimSpace(expDec)
	if modHex == "" || expDec == "" {
		return nil, fmt.Errorf("%w: 模数或指数为空", ErrInvalidPubKey)
	}

	n := new(big.Int)
	if _, ok := n.SetString(modHex, 16); !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("%w: 模数不是合法的 hex", ErrInvalidPubKey)
	}

	e := new(big.Int)
	if _, ok := e.SetString(expDec, 10); !ok || e.Sign() <= 0 {
		return nil, fmt.Errorf("%w: 指数不是合法的十进制", ErrInvalidPubKey)
	}
	if !e.IsInt64() || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: 指数超出范围", ErrInvalidPubKey)
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// EncryptPassword 按官方算法加密口令，返回小写 hex 密文。
//
// antiReplayRand 来自当前这次 authConfig 响应；它是一次性的，网关失败时
// 会回传新值，调用方必须用新值重新加密，否则服务端拒绝（§11.4）。
//
// 这里刻意使用 PKCS#1 v1.5 而非 OAEP：这不是我们自己选的，
// 是网关的既定行为。官方客户端用 rsa.EncryptPKCS1v15 等价的分块方式
// 加密，换成 OAEP 网关直接解不开。go vet 的弃用提示在此可以忽略。
func EncryptPassword(pub *rsa.PublicKey, password, antiReplayRand string) (string, error) {
	if pub == nil {
		return "", ErrInvalidPubKey
	}

	plain := password + "_" + antiReplayRand

	size := pub.Size()
	if plainChunkSize > size-11 {
		// 密钥太短，无法按官方常量分块。宁可报错也不静默改动分块大小——
		// 改了之后网关解不开，错误会出现在很难排查的远端。
		return "", fmt.Errorf("aTrust: 网关密钥长度 %d 字节，小于算法要求的下限", size)
	}

	var out strings.Builder
	for i := 0; i < len(plain); i += plainChunkSize {
		end := i + plainChunkSize
		if end > len(plain) {
			end = len(plain)
		}
		block, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plain[i:end]))
		if err != nil {
			return "", fmt.Errorf("aTrust: RSA 加密失败: %w", err)
		}
		out.WriteString(hex.EncodeToString(block))
	}
	return out.String(), nil
}
