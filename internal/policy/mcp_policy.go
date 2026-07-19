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

func RequireDisconnect(value model.ConnectionProfile) error {
	if err := RequireProfile(value); err != nil {
		return err
	}
	if !value.MCPPolicy.AllowDisconnect {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "此连接配置未授权 MCP 断开 VPN", "mcp_policy", false)
	}
	return nil
}
