package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Status struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type Controller struct {
	core       CoreService
	secrets    secrets.Store
	audit      *Auditor
	mu         sync.Mutex
	server     *http.Server
	listener   net.Listener
	port       int
	execSlots  chan struct{}
	sessionMu  sync.Mutex
	sessions   map[string]struct{}
	uploadMu   sync.Mutex
	uploadJobs map[string]string
}

func NewController(core CoreService, secretStore secrets.Store, auditor *Auditor) *Controller {
	return &Controller{
		core: core, secrets: secretStore, audit: auditor, execSlots: make(chan struct{}, 4), sessions: make(map[string]struct{}), uploadJobs: make(map[string]string),
	}
}

func (c *Controller) Start(ctx context.Context, port int) (Status, error) {
	if port < 1024 || port > 65535 {
		return Status{}, model.NewAppError("PROFILE_INVALID", "MCP 端口必须为 1024-65535", "mcp_start", false)
	}
	token, err := c.token(ctx)
	if err != nil {
		return Status{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server != nil {
		return c.statusLocked(), nil
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return Status{}, model.NewAppError("MCP_BUSY", "MCP 本机端口无法监听", "mcp_start", true).WithDetails(map[string]any{"port": port})
	}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "LabRemote", Version: "1.1.0"}, nil)
	addTools(mcpServer, c)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", securityMiddleware(mcpHandler, string(token), port, newRateLimiter(120)))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 * 1024,
	}
	c.server = server
	c.listener = listener
	c.port = port
	go func() {
		_ = server.Serve(listener)
	}()
	return c.statusLocked(), nil
}

func (c *Controller) Stop(ctx context.Context) error {
	c.mu.Lock()
	server := c.server
	c.server = nil
	listener := c.listener
	c.listener = nil
	c.port = 0
	c.mu.Unlock()
	if server == nil {
		return nil
	}
	shutdownContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	if shutdownErr != nil {
		// 超时后关闭剩余请求，确保不会在资源快照之后新增 MCP 任务。
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	c.uploadMu.Lock()
	jobIDs := make([]string, 0, len(c.uploadJobs))
	for jobID := range c.uploadJobs {
		jobIDs = append(jobIDs, jobID)
	}
	c.uploadJobs = make(map[string]string)
	c.uploadMu.Unlock()
	c.core.CloseMCPUploads(ctx, jobIDs)
	c.core.CloseMCPSessions(ctx)
	c.sessionMu.Lock()
	c.sessions = make(map[string]struct{})
	c.sessionMu.Unlock()
	if errors.Is(shutdownErr, net.ErrClosed) || errors.Is(shutdownErr, http.ErrServerClosed) {
		return nil
	}
	return shutdownErr
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked()
}

func (c *Controller) statusLocked() Status {
	if c.server == nil {
		return Status{}
	}
	return Status{Enabled: true, Port: c.port, Address: fmt.Sprintf("http://127.0.0.1:%d/mcp", c.port)}
}

func (c *Controller) ClientConfig(ctx context.Context) (string, error) {
	c.mu.Lock()
	status := c.statusLocked()
	c.mu.Unlock()
	if !status.Enabled {
		return "", model.NewAppError("MCP_DISABLED", "MCP 服务尚未开启", "mcp_config", false)
	}
	token, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("{\n  \"mcpServers\": {\n    \"labremote\": {\n      \"url\": %q,\n      \"headers\": {\n        \"Authorization\": %q\n      }\n    }\n  }\n}", status.Address, "Bearer "+string(token)), nil
}

func (c *Controller) AccessToken(ctx context.Context) (string, error) {
	token, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (c *Controller) RegenerateToken(ctx context.Context) (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("生成 MCP 令牌失败: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(value)
	secrets.Zero(value)
	if err := c.secrets.Put(ctx, model.MCPTokenKey(), []byte(token)); err != nil {
		return "", fmt.Errorf("保存 MCP 令牌失败: %w", err)
	}
	// 已启动时必须重启，使旧令牌立即失效。
	c.mu.Lock()
	port := c.port
	running := c.server != nil
	c.mu.Unlock()
	if running {
		if err := c.Stop(ctx); err != nil && !strings.Contains(err.Error(), "closed") {
			return "", err
		}
		if _, err := c.Start(ctx, port); err != nil {
			return "", err
		}
	}
	return token, nil
}

func (c *Controller) token(ctx context.Context) ([]byte, error) {
	token, err := c.secrets.Get(ctx, model.MCPTokenKey())
	if err == nil && len(token) >= 32 {
		return token, nil
	}
	if err != nil && err != secrets.ErrNotFound {
		return nil, err
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("生成 MCP 令牌失败: %w", err)
	}
	generated := base64.RawURLEncoding.EncodeToString(value)
	secrets.Zero(value)
	if err := c.secrets.Put(ctx, model.MCPTokenKey(), []byte(generated)); err != nil {
		return nil, err
	}
	return c.secrets.Get(ctx, model.MCPTokenKey())
}
