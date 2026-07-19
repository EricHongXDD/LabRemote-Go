package model

import "time"

type VPNState string

const (
	VPNDisconnected  VPNState = "disconnected"
	VPNPreparing     VPNState = "preparing"
	VPNDialing       VPNState = "dialing"
	VPNConnected     VPNState = "connected"
	VPNReconnecting  VPNState = "reconnecting"
	VPNDisconnecting VPNState = "disconnecting"
	VPNFailed        VPNState = "failed"
)

type VPNStatus struct {
	ProfileID    string    `json:"profile_id"`
	State        VPNState  `json:"state"`
	ErrorCode    string    `json:"error_code,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	Interface    string    `json:"interface,omitempty"`
	RouteReady   bool      `json:"route_ready"`
	ReferenceNum int       `json:"reference_num"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ConnectionStatus struct {
	ProfileID       string    `json:"profile_id"`
	VPN             VPNStatus `json:"vpn"`
	SSHConnected    bool      `json:"ssh_connected"`
	UISessions      int       `json:"ui_sessions"`
	MCPSessions     int       `json:"mcp_sessions"`
	ActiveCommands  int       `json:"active_commands"`
	ActiveTransfers int       `json:"active_transfers"`
	BrowserSessions int       `json:"browser_sessions"`
}

type TerminalChunk struct {
	SessionID  string `json:"session_id"`
	Sequence   uint64 `json:"sequence"`
	DataBase64 string `json:"data_base64"`
}

type ExecRequest struct {
	ProfileID      string        `json:"profile_id"`
	Command        string        `json:"command"`
	Timeout        time.Duration `json:"timeout"`
	MaxOutputBytes int           `json:"max_output_bytes"`
}

type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
}

type SessionReadResult struct {
	Cursor     uint64 `json:"cursor"`
	DataBase64 string `json:"data_base64"`
	Open       bool   `json:"open"`
	Truncated  bool   `json:"truncated"`
	Error      string `json:"error,omitempty"`
}
