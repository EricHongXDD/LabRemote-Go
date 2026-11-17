package model

// BrowserAccess 保存网页代理的完整入口；访问链接包含令牌，不能写入日志。
type BrowserAccess struct {
	AccessID  string `json:"access_id"`
	ProfileID string `json:"profile_id"`
	TargetURL string `json:"target_url"`
	AccessURL string `json:"access_url"`
}
