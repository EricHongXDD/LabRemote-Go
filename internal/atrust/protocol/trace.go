// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// trace.go — trace id 生成。
//
// 网关每条响应都带 traceId，客户端在每个请求上带 X-Sdp-Traceid。
// 两者的作用是把一次登录在多份日志里串起来；格式是 8 位小写 hex
// （实测样本一律 8 位）。

import (
	"crypto/rand"
	"encoding/hex"
)

// newTraceID 生成 8 hex 字符的 trace id。
//
// crypto/rand 而非 math/rand：trace id 会出现在网关日志里，
// 可预测的序列会让日志聚合出现碰撞。取 4 字节正好 8 hex。
func newTraceID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// trace id 只用于日志串联，生成失败不影响协议正确性。
		return "00000000"
	}
	return hex.EncodeToString(b)
}
