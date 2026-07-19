package mcpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"
)

type Auditor struct {
	logger *slog.Logger
}

func NewAuditor(logger *slog.Logger) *Auditor { return &Auditor{logger: logger} }

func (a *Auditor) Tool(tool, profileID, command, result string, exitCode int, duration time.Duration) {
	if a == nil || a.logger == nil {
		return
	}
	attributes := []any{
		"tool", tool,
		"profile_id", profileID,
		"result", result,
		"exit_code", exitCode,
		"duration_ms", duration.Milliseconds(),
	}
	if command != "" {
		sum := sha256.Sum256([]byte(command))
		attributes = append(attributes, "command_sha256", hex.EncodeToString(sum[:]))
	}
	a.logger.Info("mcp_tool_call", attributes...)
}
