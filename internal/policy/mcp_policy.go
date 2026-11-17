package policy

import (
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func RequireProfile(value model.ConnectionProfile) error {
	if !value.MCPPolicy.EnabledForProfile {
		return model.NewAppError("MCP_PROFILE_FORBIDDEN", "此连接配置未授权给 MCP", "mcp_policy", false)
	}
	return nil
}

func RequireExec(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowExec {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 执行命令", "mcp_policy", false)
	}
	return nil
}

func RequireInteractive(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowInteractive {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 交互会话", "mcp_policy", false)
	}
	return nil
}

func RequireFileUpload(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowFileUpload {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 上传文件", "mcp_policy", false)
	}
	return nil
}

func RequireFileDownload(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowFileDownload {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 下载文件", "mcp_policy", false)
	}
	return nil
}

func RequireDisconnect(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowDisconnect {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 断开 VPN", "mcp_policy", false)
	}
	return nil
}

func RequireBrowser(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowBrowser {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 网页访问", "mcp_policy", false)
	}
	return nil
}

func RequireFileBrowse(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowFileUpload && !value.MCPPolicy.AllowFileDownload {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "浏览远端目录需要 MCP 文件上传或下载权限", "mcp_policy", false)
	}
	return nil
}
