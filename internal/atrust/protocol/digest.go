// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// digest.go — 隧道认证用到的小型哈希工具。
//
// 这些值不参与安全决策，只是用来把本机进程路径变成一个稳定标识
// （官方客户端用 SHA256(进程路径) 作 fingerprint，用 MD5(deviceId)
// 作 connectionId 的前缀）。因此不需要加盐或防碰撞设计，需要的是
// 与客户端**逐字节一致**的输出格式：大写十六进制。

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// upperSHA256Hex 返回 s 的 SHA256，大写十六进制。
func upperSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// upperMD5Hex 返回 s 的 MD5，大写十六进制。
func upperMD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// jsonEscape 把字符串转义成 JSON 字符串字面量的内部形式。
//
// 不用 encoding/json 的原因：隧道认证 JSON 的**字段顺序与空白**都要
// 与官方客户端一致，用 struct 序列化无法控制这一点。这里只处理
// 必须转义的字符，其余原样输出。
func jsonEscape(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u`)
				// 控制字符极少出现；补零到 4 位以保持合法 JSON。
				h := strconv.FormatInt(int64(r), 16)
				for len(h) < 4 {
					h = "0" + h
				}
				b.WriteString(h)
				continue
			}
			if !utf8.ValidRune(r) {
				b.WriteRune(utf8.RuneError)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
