// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// errors.go — 对外暴露的错误分类。
//
// 分层的意义在于：调用方需要区分"凭据错""网络不通""需要二次认证"
// 这三种情况的处理方式完全不同——前者提示用户，中者允许重试，
// 后者要切到另一个界面。把它们都压成一个 error 字符串会让上层的
// 分支逻辑退化成字符串匹配。

import "errors"

var (
	// ErrNoSession 表示当前没有有效会话（未登录或已登出）。
	ErrNoSession = errors.New("aTrust: 当前没有有效会话")

	// ErrMultiFactorRequired 表示网关要求继续下一步认证。
	// 包装在 error 里的原因会带上具体的 nextService 值。
	ErrMultiFactorRequired = errors.New("aTrust: 需要多因子认证")

	// ErrNotATrustGateway 表示目标地址看起来不是 aTrust 网关。
	// 判断依据是 /public/manifest 的 data.server 不含 "aTrust"。
	ErrNotATrustGateway = errors.New("aTrust: 目标不是 aTrust 网关")

	// ErrUnsupportedGateway 表示网关缺少本实现依赖的能力。
	ErrUnsupportedGateway = errors.New("aTrust: 网关能力不满足要求")
)

// IsMultiFactorRequired 报告 err 是否表示需要继续下一步认证。
func IsMultiFactorRequired(err error) bool { return errors.Is(err, ErrMultiFactorRequired) }

// IsNotATrustGateway 报告 err 是否因为目标不是 aTrust 网关。
func IsNotATrustGateway(err error) bool { return errors.Is(err, ErrNotATrustGateway) }
