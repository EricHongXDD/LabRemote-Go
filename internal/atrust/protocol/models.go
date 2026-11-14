// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// models.go — aTrust 控制面的报文结构。
//
// 字段集合与取值直接来自对真实网关和 mock 的双向实测（见
// ATRUST_PROTOCOL_ANALYSIS.md §20.2、§22.1）。这里刻意保留真实响应的
// 几处"类型怪癖"，因为客户端按这些类型解析，写错就失败：
//
//   - pubKeyExp 是十进制字符串 "65537"，不是 hex，也不是数字
//   - enableClientAutoStart 是字符串 "0"，不是布尔
//   - certDomains 必须是数组（可为空），不能是 null
//   - security.csrfToken 是非空 UUID 字符串
//
// 改动这些类型前请先读 §23.2。

// Envelope 是 aTrust 所有 API 的统一外壳。
//
// 2026-10-21 二次实测修正：authConfig 的 data 是**平铺**的 35 键，
// 不是早期文档推测的 {type, data, first} 三层结构。客户端 useInitHelp
// 直接断言 data.firstAuth 是数组、data.domains 是数组。
type Envelope[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
	TraceID string `json:"traceId,omitempty"`
}

// Manifest 对应 GET /public/manifest 的 data。
//
// Server 含 "aTrust" 子串是识别 aTrust 网关的主要依据；
// Capacities 是能力协商表，客户端只读取自己关心的键。
type Manifest struct {
	Server     string            `json:"server"`
	Version    string            `json:"version"`
	Capacities map[string]any    `json:"capacities"`
	Extra      map[string]string `json:"-"`
}

// AuthConfig 对应 GET /passport/v1/public/authConfig 的 data（35 键平铺）。
type AuthConfig struct {
	FirstAuth      []string `json:"firstAuth"`
	DefaultDomain  string   `json:"defaultDomain"`
	Domains        []string `json:"domains"`
	AuthServerList []struct {
		LoginDomain string `json:"loginDomain"`
		AuthID      string `json:"authId"`
		AuthType    string `json:"authType"` // 如 "auth/psw"
		SubType     string `json:"subType"`
		AuthName    string `json:"authName"`
		LoginURL    string `json:"loginUrl"`
	} `json:"authServerInfoList"`

	PubKey                string `json:"pubKey"`    // 512 hex，RSA 模数
	PubKeyExp             string `json:"pubKeyExp"` // "65537"，十进制字符串
	AntiReplayRand        string `json:"antiReplayRand"`
	ClientVerifyCode      string `json:"clientVerifyCode"`
	ClientInstallMode     string `json:"clientInstallMode"`
	EnableClientAutoStart string `json:"enableClientAutoStart"` // "0"
	GUID                  string `json:"guid"`
	UnitID                string `json:"unitid"`
	PassportTokenEnable   int    `json:"passportTokenEnable"`
	ThirdAuthQrcodeTime   int    `json:"thirdAuthQrcodeTimeout"`
	Security              struct {
		CSRFToken string `json:"csrfToken"`
	} `json:"security"`
	PortalProtocolKey  string         `json:"portalProtocolKey"`
	AntiMITMAttackData AntiMITMData   `json:"antiMITMAttackData"`
	CertData           map[string]any `json:"certData"`
	USBKeyData         map[string]any `json:"usbKeyData"`
	WebDiagnosisConf   map[string]any `json:"webDiagnosisConf"`
	AutoRedirect       bool           `json:"autoRedirect"`

	CertDomains []string `json:"certDomains"` // 必须数组；空 ⇒ 不启用证书登录
	CertPort    string   `json:"certPort"`

	TLSConfig int `json:"tlsConfig"`
	IsLogin   int `json:"isLogin"`
}

// AntiMITMData 对应 authConfig.data.antiMITMAttackData（10 个字段）。
//
// Enable 控制**渲染层**是否发起反中间人握手；它不控制客户端在登录后
// 对 clientResource 等响应做的验签（那是 SdpcTerminalTrust 的事，
// 且只看本地库里的 signKey）。见 §24.15、§27.2。
//
// 本实现在此结构上只做**读取与记录**：不生成 signKey，不计算 mitmSig。
// enable=0 的网关不会要求它们（§27.5）。
type AntiMITMData struct {
	Enable             int    `json:"enable"`
	DevicePubKeyMod    string `json:"devicePubKeyMod"`
	DevicePubKeyExp    string `json:"devicePubKeyExp"`
	RSACert            string `json:"rsaCert"`
	SM2EncCert         string `json:"sm2encCert"`
	Challenge          string `json:"challenge"`
	EncryptedChallenge string `json:"encryptedChallenge"`
	Ticket             string `json:"ticket"`
	AntiMITMRequest    bool   `json:"antiMITMRequest"`
	MitmSig            string `json:"mitmSig"`
}

// PSWRequest 对应 POST /passport/v1/auth/psw 的请求体。
//
// Password 是**密文**：RSA/PKCS#1 v1.5，明文为 "<password>_<antiReplayRand>"，
// 每 245 字符分块，块密文以小写 hex 首尾拼接。§5 已由官方客户端实测证实。
type PSWRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	RememberPwd    string `json:"rememberPwd"` // "0" / "1"，字符串
	GraphCheckCode string `json:"graphCheckCode"`
}

// PSWResponse 是 POST /passport/v1/auth/psw 的 data。
//
// NextService 必须落在客户端的**分发表**内：
//
//	{"auth/authCheck": …, "auth/accessCheck": …}
//
// 任何其它值都会让客户端既不调 authCheck 也不调 accessCheck，
// 直接"成功"结束——界面永远停在登录中，且没有任何错误日志（§24.3）。
type PSWResponse struct {
	SidTicket   string `json:"sidTicket"`
	NextService string `json:"nextService"`
	Random      string `json:"random,omitempty"`
	// 部分网关在失败时回传新的 antiReplayRand，客户端必须用新值重算密文。
	AntiReplayRand string `json:"antiReplayRand,omitempty"`
}

// AuthCheckData 对应 GET /passport/v1/auth/authCheck 的 data。
//
// NextService 置空是**刻意的**：客户端只有在 nextService 为空、且
// onlineInfo.isOnline 为假时，才会执行 detectClient() + startClient()
// 拉起原生 agent（§24.3）。
//
// ActionType / Action / PolicyID / Reason / SidTicket 这五列缺一不可，
// 否则客户端打 "acl data column error"。
type AuthCheckData struct {
	NextService string `json:"nextService"`
	ActionType  string `json:"actionType"`
	Action      string `json:"action"`
	PolicyID    string `json:"policyId"`
	Reason      string `json:"reason"`
	SidTicket   string `json:"sidTicket"`
}

// OnlineInfo 对应 GET /passport/v1/user/onlineInfo 的 data。
//
// 未登录时必须是 {"isOnline": false} **且 code=0** —— 未登录是正常答案，
// 不是会话失效，用错误码会触发客户端的错误分支（§24.4）。
type OnlineInfo struct {
	IsOnline bool   `json:"isOnline"`
	Username string `json:"username,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Addr     string `json:"addr,omitempty"`
	// 部分网关下发登录后才会出现的字段；用指针区分"缺失"与"空值"。
	TunnelStatus *string `json:"tunnelStatus,omitempty"`
}

// ClientResource 对应 POST /controller/v1/user/clientResource 的 data。
//
// 资源树的具体形状尚未与真实网关比对过（mock 只提供了最小可用集）。
// 这里保持原始 JSON 透传，由上层决定如何投影成 {name, host, port}，
// 避免过早固化一个可能错误的模型。
type ClientResource struct {
	Raw map[string]any `json:"-"`
}

// SessionExchange 是 sessionIdExchange / ticketExchange 的响应 data。
//
// 两者的语义不同（§24.12）：
//   - sessionIdExchange：客户端**不读**响应体，只关心成功与否
//   - ticketExchange：客户端**要读** data.sidTicket，再交给本地 agent
//
// 因此 ticketExchange 必须返回这个字段。
type SessionExchange struct {
	SidTicket string `json:"sidTicket,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// LogoutRequest 对应 POST /passport/v1/user/logout 的请求体。
type LogoutRequest struct {
	LogoutAll bool `json:"logoutAll,omitempty"`
}
