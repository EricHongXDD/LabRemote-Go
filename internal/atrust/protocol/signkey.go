// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// signkey.go — 从 antiMITMAttackData 派生 signKey。
//
// 这个值在官方客户端里有三个用途：
//
//	1. mitmSig           —— 网关侧反中间人校验（我们作为客户端不需要）
//	2. X-Response-Sig    —— 校验网关响应（我们作为客户端不需要）
//	3. X-Request-Sig     —— 数据面隧道认证的可选签名（我们可能需要）
//
// 算法已在 §29.2 / §29.12 由三份独立开源实现交叉验证：
//
//	first   = SHA256(pubMod + pubExp + SIG_SALT)
//	signKey = SHA256(pubMod + pubExp + SIG_SALT)  XOR  SHA256(UPPER_HEX(first) + challenge)
//
// 输出是 32 字节；作为 hex 字符串使用时是大写。
//
// ⚠ 这里**只做派生**，不参与任何校验。作为客户端，我们不对网关下发的内容
// 做反中间人判定——那是网关的职责。派生它只是为了在数据面请求上带出
// X-Request-Sig（某些网关会校验，某些不会；见 geektrust §6.2 与 libreatrust）。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// signatureSalt 是 signKey 派生用的固定盐。
//
// 来源：zju-connect anti_mitm.go、libreatrust sign.rs、geektrust §10.1
// 三处给出同一个常量。§27.4 记录的"按 16 字节分块重排"是它在 DLL 里的
// 存储形态，不是另一个值。
const signatureSalt = "3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq"

// deriveSignKey 按 §10.1 派生 signKey（32 字节）。
//
// antiMITMAttackData 里的字段名是设备公钥，别与 authConfig.pubKey 混淆：
// 后者是**登录口令加密**用的网关公钥，前者是网关发给客户端、用于
// 反中间人材料的设备公钥。
func deriveSignKey(d AntiMITMData) []byte {
	if d.DevicePubKeyMod == "" || d.Challenge == "" {
		return nil
	}

	first := sha256.Sum256([]byte(d.DevicePubKeyMod + d.DevicePubKeyExp + signatureSalt))
	firstHex := strings.ToUpper(hex.EncodeToString(first[:]))

	second := sha256.Sum256([]byte(firstHex + d.Challenge))

	key := make([]byte, sha256.Size)
	for i := range key {
		key[i] = first[i] ^ second[i]
	}
	return key
}

// setSignKeyFromAntiMITM 在拿到 authConfig 后派生并记录 signKey。
func (c *Client) setSignKeyFromAntiMITM(d AntiMITMData) {
	key := deriveSignKey(d)
	hexKey := ""
	if len(key) > 0 {
		hexKey = strings.ToUpper(hex.EncodeToString(key))
	}

	c.mu.Lock()
	c.signKey = hexKey
	c.mu.Unlock()

	if hexKey == "" {
		c.logf("aTrust signKey 未派生（antiMITMAttackData 缺少设备公钥或 challenge）")
	} else {
		c.logf("aTrust signKey 已派生（%d 字节）", len(key))
	}
}

// SignKeyHex 返回当前 signKey 的大写十六进制形式（未派生时为空）。
func (c *Client) SignKeyHex() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.signKey
}

// requestSig 计算 X-Request-Sig：HMAC-SHA256(hex_decode(signKey), msg) 的大写 hex。
//
// 与 geektrust §10.3 一致：消息是 **pathWithQuery + body**，密钥是 signKey
// 的十六进制**解码**字节。注意这与响应侧的 X-Response-Sig 不同——
// 那个的消息只有 body，没有路径。
func (c *Client) requestSig(msg []byte) string {
	c.mu.RLock()
	hexKey := c.signKey
	c.mu.RUnlock()

	if hexKey == "" {
		return ""
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}
