// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// login.go — 登录链的编排。
//
// 这里的顺序不是设计出来的，是**实测出来的**。每一步为什么存在、
// 少了它会怎样，都记在 ATRUST_PROTOCOL_ANALYSIS.md 里。改动顺序前
// 请先读 §24.13 的时序表与 §25.3 的七轮根因递进。
//
// 完整的实测时序（官方客户端连 mock，跑通到 user login success）：
//
//	manifest.js → manifest → authConfig → psw → authCheck
//	→ onlineInfo → clientResource → sessionIdExchange
//	→ ticketExchange → （agent 上线）
//
// 本包实现到 clientResource 为止；sessionIdExchange / ticketExchange
// 之后的那一步（让本地 agent 上线）不属于协议范畴，由产品层决定。

import (
	"context"
	"fmt"
	"strings"
)

// LoginResult 是一次成功登录的产物。
type LoginResult struct {
	SidTicket string
	Username  string
	// Resources 是资源树原文。形状尚未与真实网关比对，见 ClientResource。
	Resources map[string]any
	// AuthConfig 是本次登录使用的配置快照。
	AuthConfig *AuthConfig
}

// Detect 判断目标地址是否为 aTrust 网关。
//
// 依据是 /public/manifest 的 data.server 含 "aTrust"。这是唯一可靠的
// 自动识别手段：不能靠端口或路径探测，因为 aTrust 与 V5VPN 都用 443，
// 且都会返回 JSON。
func (c *Client) Detect(ctx context.Context) error {
	m, err := c.Manifest(ctx)
	if err != nil {
		return err
	}
	if !strings.Contains(m.Server, "aTrust") {
		return fmt.Errorf("%w: server=%q", ErrNotATrustGateway, m.Server)
	}
	return nil
}

// Authenticate 执行到 onlineInfo 为止的认证链，**不拉资源树**。
//
// 单独拆出来的原因是 UI 的时序：登录请求有 12 秒上限，而 clientResource
// 在冷启动的网关上可能更慢。先让界面进入"已连接、正在拉取资源"，
// 再在后台补资源，和 V5VPN 侧的 enterConnected / loadResources 是同一套语义。
//
// 步骤与理由（每一步都是实测必需的）：
//
//  1. authConfig —— 取公钥、antiReplayRand、csrfToken。
//     每次登录前都重新拉，因为这些值是一次性的（§11.4）。
//  2. psw —— 提交 RSA 密文。成功后记录 sidTicket 并写 cookie。
//     凭据在这里落地，后续请求都靠它（§24.10）。
//  3. nextService 分支 —— 只有 auth/authCheck 与 auth/accessCheck
//     两个键被客户端认识。空串表示没有下一步。
//  4. onlineInfo —— 该端点在登录链里被调用过；它的 isOnline 结果会
//     影响客户端是否拉起原生 agent。我们作为纯客户端只需要它成功返回。
func (c *Client) Authenticate(ctx context.Context, username, password string) (*AuthConfig, error) {
	// 用户名是数据面隧道认证 JSON 的必填字段，先记下来。
	c.SetUsername(username)

	cfg, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aTrust: 获取 authConfig 失败: %w", err)
	}

	psw, err := c.LoginWithPassword(ctx, username, password)
	if err != nil {
		return nil, err
	}

	if err := c.continueAuthChain(ctx, psw.NextService); err != nil {
		return nil, err
	}

	// onlineInfo 在登录后应当为 true；为 false 说明会话没建立起来。
	// 这里不把 false 当致命错误——有些网关的 onlineInfo 有延迟——
	// 但记日志，方便排查"登录成功却拿不到资源"的情况。
	if info, err := c.OnlineInfo(ctx); err != nil {
		c.logf("aTrust onlineInfo 失败（不阻断登录）: %v", err)
	} else if !info.IsOnline {
		c.logf("aTrust onlineInfo 返回 isOnline=false（会话可能未被网关确认）")
	}

	return cfg, nil
}

// Login 执行完整的口令登录链，含资源树。
//
// 资源那一步失败不应当让登录失败：会话已经有效，资源可以稍后重试
// （与 V5VPN 侧的 ResourceFetchError 语义一致）。
func (c *Client) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	cfg, err := c.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}

	res := &LoginResult{
		SidTicket:  c.SidTicket(),
		Username:   username,
		AuthConfig: cfg,
	}

	resources, err := c.ClientResource(ctx)
	if err != nil {
		// 会话有效但资源取不到：把结果照常返回，让上层进入"已连接、
		// 资源为空、稍后重试"的状态，而不是把这个会话丢掉。
		c.logf("aTrust 资源获取失败（会话仍有效，可稍后重试）: %v", err)
	} else {
		res.Resources = resources
	}

	return res, nil
}

// continueAuthChain 处理 psw 返回的 nextService。
//
// 空串：没有下一步，直接结束。
// auth/authCheck：调 AuthCheck。
// auth/accessCheck：调 AccessCheck。
// 其它值：validateNextService 已经在 LoginWithPassword 里拦住了，
// 这里不会收到。
func (c *Client) continueAuthChain(ctx context.Context, next string) error {
	switch next {
	case "":
		return nil
	case "auth/authCheck":
		data, err := c.AuthCheck(ctx)
		if err != nil {
			return err
		}
		// authCheck 可能再给出一个 nextService；多因子场景在这里暴露。
		if data.NextService != "" {
			return fmt.Errorf("%w: %s", ErrMultiFactorRequired, data.NextService)
		}
		return nil
	case "auth/accessCheck":
		data, err := c.AccessCheck(ctx)
		if err != nil {
			return err
		}
		if data.NextService != "" {
			return fmt.Errorf("%w: %s", ErrMultiFactorRequired, data.NextService)
		}
		return nil
	default:
		// 理论上不可达：LoginWithPassword 已经校验过。
		return fmt.Errorf("aTrust: 未知的 nextService %q", next)
	}
}

// Logout 结束会话并清空本地状态。
func (c *Client) LogoutAndClear(ctx context.Context) error {
	err := c.Logout(ctx)
	c.SetSession("")
	c.mu.Lock()
	c.authConfig = nil
	c.csrfToken = ""
	c.mu.Unlock()
	return err
}
