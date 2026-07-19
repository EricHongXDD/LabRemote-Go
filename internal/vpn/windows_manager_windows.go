//go:build windows && legacy_ras

package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

const ensureVPNProfileScript = `$ErrorActionPreference = 'Stop'
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
$current = Get-VpnConnection -Name $inputValue.name -ErrorAction SilentlyContinue
if ($null -eq $current) {
  Add-VpnConnection -Name $inputValue.name -ServerAddress $inputValue.server -TunnelType L2tp -L2tpPsk $inputValue.psk -AuthenticationMethod MSChapv2 -EncryptionLevel Required -SplitTunneling -RememberCredential -Force | Out-Null
} else {
  Set-VpnConnection -Name $inputValue.name -ServerAddress $inputValue.server -TunnelType L2tp -L2tpPsk $inputValue.psk -AuthenticationMethod MSChapv2 -EncryptionLevel Required -SplitTunneling $true -RememberCredential $true -Force | Out-Null
}`

const queryVPNStatusScript = `$ErrorActionPreference = 'Stop'
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
$value = Get-VpnConnection -Name $inputValue.name -ErrorAction SilentlyContinue
if ($null -eq $value) { 'Missing' } else { $value.ConnectionStatus.ToString() }`

const disconnectVPNFallbackScript = `$ErrorActionPreference = 'Stop'
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
& "$env:SystemRoot\System32\rasdial.exe" $inputValue.name /disconnect | Out-Null`

type WindowsManager struct {
	repository profile.Repository
	secrets    secrets.Store
	states     *StateMachine
	mu         sync.Mutex
	locks      map[string]*sync.Mutex
	handles    map[string]uintptr
}

func NewWindowsManager(repository profile.Repository, secretStore secrets.Store, sink events.Sink) *WindowsManager {
	return &WindowsManager{
		repository: repository,
		secrets:    secretStore,
		states:     NewStateMachine(sink),
		locks:      make(map[string]*sync.Mutex),
		handles:    make(map[string]uintptr),
	}
}

func (m *WindowsManager) profileLock(profileID string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks[profileID] == nil {
		m.locks[profileID] = &sync.Mutex{}
	}
	return m.locks[profileID]
}

func (m *WindowsManager) EnsureProfile(ctx context.Context, value model.ConnectionProfile) error {
	psk, err := m.secrets.Get(ctx, model.VPNPSKKey(value.ID))
	if err != nil {
		return model.NewAppError("SECRET_NOT_FOUND", "未找到 VPN 预共享密钥", "vpn_profile", false)
	}
	defer secrets.Zero(psk)
	password, err := m.secrets.Get(ctx, model.VPNPasswordKey(value.ID))
	if err != nil {
		return model.NewAppError("SECRET_NOT_FOUND", "未找到 VPN 密码", "vpn_profile", false)
	}
	defer secrets.Zero(password)
	_, err = runPowerShellJSON(ctx, ensureVPNProfileScript, map[string]string{
		"name":   value.VPN.ConnectionName,
		"server": value.VPN.ServerAddress,
		"psk":    string(psk),
	})
	if err != nil {
		return model.NewAppError("VPN_PROFILE_CREATE_FAILED", "创建或更新 Windows VPN 配置失败", "vpn_profile", true).WithDetails(map[string]any{"cause": err.Error()})
	}
	if err := setRASCredentials(value.VPN.ConnectionName, value.VPN.Username, password); err != nil {
		return model.NewAppError("VPN_PROFILE_CREATE_FAILED", "保存 Windows VPN 拨号凭据失败", "vpn_profile", true).WithDetails(map[string]any{"cause": err.Error()})
	}
	if err := setRASPreSharedKey(value.VPN.ConnectionName, psk); err != nil {
		return model.NewAppError("VPN_PROFILE_CREATE_FAILED", "保存 L2TP/IPsec 预共享密钥失败", "vpn_profile", true).WithDetails(map[string]any{"cause": err.Error()})
	}
	return nil
}

func (m *WindowsManager) Connect(ctx context.Context, profileID string) (model.VPNStatus, error) {
	lock := m.profileLock(profileID)
	lock.Lock()
	defer lock.Unlock()
	status, _ := m.Status(ctx, profileID)
	if status.State == model.VPNConnected {
		return status, nil
	}
	m.states.Set(profileID, model.VPNPreparing, "")
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		m.states.Set(profileID, model.VPNFailed, "PROFILE_NOT_FOUND")
		return m.states.Get(profileID), err
	}
	if err := m.EnsureProfile(ctx, value); err != nil {
		m.states.Set(profileID, model.VPNFailed, appErrorCode(err))
		return m.states.Get(profileID), err
	}
	if target := net.ParseIP(strings.Trim(value.SSH.ServerAddress, "[]")); target != nil {
		if err := ensureHostRoute(ctx, value.VPN.ConnectionName, target); err != nil {
			m.states.Set(profileID, model.VPNFailed, "VPN_ROUTE_FAILED")
			return m.states.Get(profileID), model.NewAppError("VPN_ROUTE_FAILED", "无法添加 SSH 目标主机路由", "vpn_route", true).WithDetails(map[string]any{"cause": err.Error()})
		}
	}
	m.states.Set(profileID, model.VPNDialing, "")
	password, err := m.secrets.Get(ctx, model.VPNPasswordKey(profileID))
	if err != nil {
		m.states.Set(profileID, model.VPNFailed, "SECRET_NOT_FOUND")
		return m.states.Get(profileID), model.NewAppError("SECRET_NOT_FOUND", "未找到 VPN 密码", "vpn_dial", false)
	}
	handle, err := dialRAS(ctx, value.VPN.ConnectionName, value.VPN.Username, password)
	if err != nil {
		code := appErrorCode(err)
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "超时") {
			code = "VPN_TIMEOUT"
			err = model.NewAppError("VPN_TIMEOUT", "VPN 在 30 秒内未进入已连接状态", "vpn_dial", true)
		}
		m.states.Set(profileID, model.VPNFailed, code)
		return m.states.Get(profileID), err
	}
	m.mu.Lock()
	m.handles[profileID] = handle
	m.mu.Unlock()
	if net.ParseIP(strings.Trim(value.SSH.ServerAddress, "[]")) == nil {
		addresses, resolveErr := net.DefaultResolver.LookupIP(ctx, "ip", value.SSH.ServerAddress)
		if resolveErr != nil || len(addresses) == 0 {
			hangUpRAS(handle)
			m.states.Set(profileID, model.VPNFailed, "SSH_HOST_RESOLVE_FAILED")
			return m.states.Get(profileID), model.NewAppError("SSH_HOST_RESOLVE_FAILED", "VPN 已连接，但无法解析 SSH 服务器地址", "vpn_route", true)
		}
		for _, address := range addresses {
			if err := ensureHostRoute(ctx, value.VPN.ConnectionName, address); err != nil {
				hangUpRAS(handle)
				m.states.Set(profileID, model.VPNFailed, "VPN_ROUTE_FAILED")
				return m.states.Get(profileID), model.NewAppError("VPN_ROUTE_FAILED", "VPN 已连接，但无法添加目标服务器路由", "vpn_route", true)
			}
		}
	}
	status = m.states.Update(profileID, func(current *model.VPNStatus) {
		current.State = model.VPNConnected
		current.RouteReady = true
		current.ErrorCode = ""
	})
	return status, nil
}

func (m *WindowsManager) Status(ctx context.Context, profileID string) (model.VPNStatus, error) {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return m.states.Get(profileID), err
	}
	connection, connected, rasErr := findRASConnection(value.VPN.ConnectionName)
	if rasErr == nil && connected {
		state, stateErr := getRASConnectStatus(connection.Handle)
		if stateErr != nil {
			return m.states.Get(profileID), stateErr
		}
		connected = state.State == rasStateConnected
	} else if rasErr != nil {
		// RAS 枚举失败时保留 VPNClient 查询作为兼容性兜底。
		output, queryErr := runPowerShellJSON(ctx, queryVPNStatusScript, map[string]string{"name": value.VPN.ConnectionName})
		if queryErr != nil {
			return m.states.Get(profileID), queryErr
		}
		connected = strings.EqualFold(strings.TrimSpace(output), "Connected")
	}
	return m.states.Update(profileID, func(current *model.VPNStatus) {
		if connected {
			current.State = model.VPNConnected
		} else if current.State != model.VPNDialing && current.State != model.VPNPreparing {
			current.State = model.VPNDisconnected
			current.RouteReady = false
		}
	}), nil
}

func (m *WindowsManager) Disconnect(ctx context.Context, profileID string, _ bool) error {
	lock := m.profileLock(profileID)
	lock.Lock()
	defer lock.Unlock()
	m.states.Set(profileID, model.VPNDisconnecting, "")
	m.mu.Lock()
	handle := m.handles[profileID]
	delete(m.handles, profileID)
	m.mu.Unlock()
	if handle != 0 {
		if err := hangUpRAS(handle); err != nil {
			m.states.Set(profileID, model.VPNFailed, "VPN_DISCONNECT_FAILED")
			return err
		}
	} else {
		value, err := m.repository.Get(ctx, profileID)
		if err != nil {
			return err
		}
		fallbackCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if _, err := runPowerShellJSON(fallbackCtx, disconnectVPNFallbackScript, map[string]string{"name": value.VPN.ConnectionName}); err != nil {
			m.states.Set(profileID, model.VPNFailed, "VPN_DISCONNECT_FAILED")
			return fmt.Errorf("断开 VPN 失败: %w", err)
		}
	}
	m.states.Set(profileID, model.VPNDisconnected, "")
	return nil
}

func appErrorCode(err error) string {
	var appError *model.AppError
	if errors.As(err, &appError) {
		return appError.Code
	}
	return "VPN_CONNECT_FAILED"
}
