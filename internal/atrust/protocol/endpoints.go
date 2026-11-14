// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// endpoints.go — 控制面接口的逐个封装。
//
// 每个方法对应一个网关端点，负责构造请求、标注该端点需要的头
// （csrf / session）、并把响应解成强类型。流程编排在 login.go。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// 控制面端点路径。集中在这里便于对照规范与 mock 的接口表。
const (
	pathManifest       = "/public/manifest"
	pathManifestJS     = "/public/manifest.js"
	pathAuthConfig     = "/passport/v1/public/authConfig"
	pathPSW            = "/passport/v1/auth/psw"
	pathAuthCheck      = "/passport/v1/auth/authCheck"
	pathAccessCheck    = "/passport/v1/auth/accessCheck"
	pathOnlineInfo     = "/passport/v1/user/onlineInfo"
	pathClientResource = "/controller/v1/user/clientResource"
	pathSessionExch    = "/passport/v1/public/sessionIdExchange"
	pathTicketExch     = "/passport/v1/public/ticketExchange"
	pathLogout         = "/passport/v1/user/logout"
)

// clientQuery 是几乎所有请求都带的查询参数。
//
// 这三个值会影响网关的行为分支，照抄官方客户端的取值。
func clientQuery() url.Values {
	return url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Windows"},
		"lang":       {"zh-CN"},
	}
}

// ---------- 能力协商 ----------

// Manifest 拉取 /public/manifest。
//
// 这个接口既是能力协商，也是**识别网关类型**的主要手段：
// data.server 含 "aTrust" 才说明这是 aTrust 网关。
func (c *Client) Manifest(ctx context.Context) (*Manifest, error) {
	data, err := doJSON[Manifest](ctx, c, requestSpec{
		method: "GET", path: pathManifest, query: clientQuery(),
	})
	if err != nil {
		return nil, err
	}
	c.logf("aTrust manifest: server=%q version=%q", data.Server, data.Version)
	return data, nil
}

// EntranceConfig 解析 /public/manifest.js。
//
// ⚠ 这个路径返回的是 **JavaScript**，不是 JSON：
//
//	var entranceConfig = {"entrance":{"type":"portal",...},"aioClient":{...}};
//
// 前端用 <script src> 直接执行它并读 window.entranceConfig。
// 返回 JSON 或错误码会让前端打出
// "window.entranceConfig.entrance undefined, api manifest.js data error"
// 并退回 Portal 默认分支（§22.2）。
//
// 这里只做"取到并提取 JSON 字面量"，不执行任何 JS。
func (c *Client) EntranceConfig(ctx context.Context) (map[string]any, error) {
	raw, err := c.do(ctx, requestSpec{
		method: "GET", path: pathManifestJS, query: clientQuery(), rawBody: true,
	})
	if err != nil {
		return nil, err
	}

	s := string(raw)
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("aTrust: manifest.js 里找不到 JSON 字面量: %s", truncate(s, 160))
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(s[start:end+1]), &m); err != nil {
		return nil, fmt.Errorf("aTrust: manifest.js 里的字面量不是合法 JSON: %w", err)
	}
	return m, nil
}

// ---------- 配置 ----------

// FetchAuthConfig 拉取 /passport/v1/public/authConfig（GET，35 键平铺）。
//
// ⚠ 必须用 GET：POST 是另一条通道（ticket 交换），data 恒为 {}。
// 照抄 POST 就会拿到空配置，客户端断言 firstAuth/domains 是数组时失败
// （§22.1）。
//
// 每次调用都会刷新 antiReplayRand 与 csrfToken，因此**每次登录前都应重新拉一次**。
func (c *Client) FetchAuthConfig(ctx context.Context) (*AuthConfig, error) {
	q := clientQuery()
	q.Set("needTicket", "1")

	cfg, err := doJSON[AuthConfig](ctx, c, requestSpec{
		method: "GET", path: pathAuthConfig, query: q,
	})
	if err != nil {
		return nil, err
	}

	c.setAuthConfig(cfg)
	// signKey 由 antiMITMAttackData 本地派生（§29.2），数据面请求签名要用。
	c.setSignKeyFromAntiMITM(cfg.AntiMITMAttackData)
	c.logf("aTrust authConfig: domains=%v firstAuth=%v randLen=%d",
		cfg.Domains, cfg.FirstAuth, len(cfg.AntiReplayRand))
	return cfg, nil
}

// ---------- 登录 ----------

// LoginWithPassword 提交口令。
//
// password 是**明文**，本方法内部完成 RSA 加密（§5）。调用方不需要
// 关心 antiReplayRand 的拼接与分块。
//
// 成功后自动记录 sidTicket 并写入 cookie jar —— 这是登录链能继续的
// 前提：渲染层的后续请求体里 token 恒为空串，网关只认 cookie（§24.10）。
func (c *Client) LoginWithPassword(ctx context.Context, username, password string) (*PSWResponse, error) {
	cfg := c.AuthConfig()
	if cfg == nil {
		return nil, fmt.Errorf("aTrust: 登录前必须先调用 FetchAuthConfig")
	}

	pub, err := ParsePublicKey(cfg.PubKey, cfg.PubKeyExp)
	if err != nil {
		return nil, err
	}

	cipherHex, err := EncryptPassword(pub, password, cfg.AntiReplayRand)
	if err != nil {
		return nil, err
	}

	resp, err := doJSON[PSWResponse](ctx, c, requestSpec{
		method:   "POST",
		path:     pathPSW,
		query:    clientQuery(),
		jsonBody: PSWRequest{Username: username, Password: cipherHex, RememberPwd: "0"},
		withCSRF: true,
	})
	if err != nil {
		return nil, err
	}

	if resp.SidTicket != "" {
		c.SetSession(resp.SidTicket)
		c.logf("aTrust 登录成功: user=%s nextService=%q", username, resp.NextService)
	}

	if err := validateNextService(resp.NextService); err != nil {
		return nil, err
	}
	return resp, nil
}

// validateNextService 校验网关给的下一个服务名是否在客户端的**分发表**内。
//
// 分发表是硬编码的两个键：
//
//	{"auth/authCheck": …, "auth/accessCheck": …}
//
// 空串是合法的（表示没有下一步，由 onlineInfo 决定是否拉起 agent）。
// 其它任何值——包括形似的 "auth/checkAccess"——都会让客户端既不调
// authCheck 也不调 accessCheck，直接"成功"结束；界面永远停在登录中，
// 且**没有任何错误日志**（§24.3）。
//
// 提前在本地拦住这种值，可以让问题在这里以明确的错误暴露出来，
// 而不是表现为一个沉默的卡死。
func validateNextService(next string) error {
	switch next {
	case "", "auth/authCheck", "auth/accessCheck":
		return nil
	default:
		return fmt.Errorf(
			"aTrust: 网关返回了未知的 nextService %q；客户端只认识 "+
				"auth/authCheck 与 auth/accessCheck，其它值会导致登录链静默中断",
			next)
	}
}

// AuthCheck 执行权限复核。
//
// 返回的 AuthCheckData.NextService 若仍非空，说明还有下一步认证
// （短信、令牌、二次确认等），需要调用方继续处理——本包目前只实现
// 口令单步，遇到多因子会以 ErrMultiFactorRequired 返回。
func (c *Client) AuthCheck(ctx context.Context) (*AuthCheckData, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}

	data, err := doJSON[AuthCheckData](ctx, c, requestSpec{
		method:      "GET",
		path:        pathAuthCheck,
		query:       clientQuery(),
		withSession: true,
	})
	if err != nil {
		return nil, err
	}

	if data.NextService != "" {
		return data, fmt.Errorf("%w: %s", ErrMultiFactorRequired, data.NextService)
	}
	return data, nil
}

// AccessCheck 是 authCheck 的备用分支（nextService 为 auth/accessCheck 时使用）。
func (c *Client) AccessCheck(ctx context.Context) (*AuthCheckData, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	return doJSON[AuthCheckData](ctx, c, requestSpec{
		method:      "POST",
		path:        pathAccessCheck,
		query:       clientQuery(),
		jsonBody:    map[string]any{},
		withCSRF:    true,
		withSession: true,
	})
}

// ---------- 在线状态 ----------

// OnlineInfo 查询在线状态。
//
// ⚠ 未登录时网关返回 {"isOnline": false} 且 code=0 —— 这是**正常答案**，
// 不是错误。用非 0 码表示"未登录"会触发客户端的会话失效分支（§24.4）。
func (c *Client) OnlineInfo(ctx context.Context) (*OnlineInfo, error) {
	return doJSON[OnlineInfo](ctx, c, requestSpec{
		method:      "GET",
		path:        pathOnlineInfo,
		query:       clientQuery(),
		withSession: true,
	})
}

// ---------- 资源 ----------

// ClientResource 拉取资源树。
//
// 返回原始 map 而不做结构投影：资源树的形状尚未与真实网关比对过
// （mock 只给了最小可用集），过早固化模型会把错误写进类型里。
// 上层按需读取自己认识的键即可。
//
// ★ 拿到响应后会调用 SetResources 建立路由索引——数据面的选路与
// appId 都依赖它。调用方不需要额外做什么。
func (c *Client) ClientResource(ctx context.Context) (map[string]any, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	data, err := doJSON[map[string]any](ctx, c, requestSpec{
		method:      "POST",
		path:        pathClientResource,
		query:       clientQuery(),
		jsonBody:    map[string]any{"resourceType": map[string]any{"sdpPolicy": map[string]any{}, "appList": map[string]any{}, "featureCenter": map[string]any{}}},
		withCSRF:    true,
		withSession: true,
	})
	if err != nil {
		return nil, err
	}
	c.SetResources(*data)
	return *data, nil
}

// ---------- 会话交换 ----------

// SessionIDExchange 把 sidTicket 换成会话 ID。
//
// ⚠ 两个细节都不能省（§24.12、§24.14）：
//   - 请求体是 **表单编码**，不是 JSON
//   - 响应必须让网关下发 cookie；原生 agent 紧随其后的
//     onlineInfo / passportTokenExchange 两个请求**既不带 Sid-Ticket 头，
//     也不带显式凭据**，只靠这条连接上的 cookie jar
//
// 本方法在成功后会把票据写进 jar，正是为了让后续请求能认回会话。
func (c *Client) SessionIDExchange(ctx context.Context, sidTicket string) (*SessionExchange, error) {
	if sidTicket == "" {
		sidTicket = c.SidTicket()
	}
	if sidTicket == "" {
		return nil, fmt.Errorf("aTrust: sessionIdExchange 缺少 sidTicket")
	}

	data, err := doJSON[SessionExchange](ctx, c, requestSpec{
		method:   "POST",
		path:     pathSessionExch,
		query:    clientQuery(),
		formBody: url.Values{"sidTicket": {sidTicket}},
		withCSRF: true,
	})
	if err != nil {
		return nil, err
	}
	c.installCookie(sidTicket)
	return data, nil
}

// TicketExchange 换发一次性 ticket。
//
// 与 SessionIDExchange 的语义不同：这个的**响应体会被读取**——
// 客户端取 data.sidTicket 再交给本地 agent（§24.12）。
func (c *Client) TicketExchange(ctx context.Context, sidTicket string) (*SessionExchange, error) {
	if sidTicket == "" {
		sidTicket = c.SidTicket()
	}
	if sidTicket == "" {
		return nil, fmt.Errorf("aTrust: ticketExchange 缺少 sidTicket")
	}

	data, err := doJSON[SessionExchange](ctx, c, requestSpec{
		method:   "POST",
		path:     pathTicketExch,
		query:    clientQuery(),
		formBody: url.Values{"sidTicket": {sidTicket}},
		withCSRF: true,
	})
	if err != nil {
		return nil, err
	}
	if data.SidTicket == "" {
		// mock 侧曾经的实现在这里返回空值，导致 agent 拿到空 ticket。
		// 明确报错比让下游拿着空串继续跑要好。
		return nil, fmt.Errorf("aTrust: ticketExchange 未返回 sidTicket（客户端会读它）")
	}
	return data, nil
}

// ---------- 登出 ----------

// Logout 结束会话。已登出时调用是安全的（网关通常返回 code=0）。
func (c *Client) Logout(ctx context.Context) error {
	_, err := doJSON[map[string]any](ctx, c, requestSpec{
		method:      "POST",
		path:        pathLogout,
		query:       clientQuery(),
		jsonBody:    LogoutRequest{},
		withCSRF:    true,
		withSession: true,
	})
	if err == nil {
		c.logf("aTrust 已登出")
	}
	return err
}

// ---------- 内部 ----------

// ensureSession 在发请求前确认已有会话票据。
//
// 提前报错而不是让网关返回 401：后者会被包装成一个语焉不详的 APIError，
// 而真正的原因是"忘了先登录"。
func (c *Client) ensureSession() error {
	if c.SidTicket() == "" {
		return ErrNoSession
	}
	return nil
}
