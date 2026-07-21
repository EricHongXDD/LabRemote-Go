import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {
  AcceptHostKey,
  AcceptTunnelCertificate,
  ClearSavedCredential,
	CloseBrowserAccess,
  CloseTerminal,
  ConnectAndOpenTerminal,
  ConnectionStatus,
  CopyText,
  DeleteProfile,
  DisconnectProfile,
  ExportMCPAIGuide,
  ListProfiles,
  ListRemoteDirectory,
  MCPAccessToken,
  MCPClientConfig,
  MCPStatus,
	OpenBrowserResource,
  RegenerateMCPToken,
  SaveProfile,
  SelectSSHPrivateKey,
  StartUpload,
  StartDownload,
  StartMCP,
  StopMCP,
  TestSSHConnection,
  TestTunnelConnection,
} from '../wailsjs/go/main/DesktopApp'
import {EventsOn} from '../wailsjs/runtime/runtime'
import {app as generatedApp} from '../wailsjs/go/models'
import ProfileDialog from './components/ProfileDialog'
import BrowserDialog from './components/BrowserDialog'
import ConfirmDialog from './components/ConfirmDialog'
import type {ConfirmOptions} from './components/ConfirmDialog'
import TerminalView from './components/TerminalView'
import TransferDialog from './components/TransferDialog'
import type {TransferMode} from './components/TransferDialog'
import {parseAppError} from './lib/errors'
import {usesIsolatedTunnel} from './lib/profile'
import type {ConnectionProfile, ConnectionTestResult, DownloadProgress, DownloadRequest, RemoteDirectory, SaveProfileRequest, TerminalTab, TestConnectionRequest, UploadProgress, UploadRequest} from './types'

type MCPState = {enabled: boolean; address: string; port: number}
type StatusValue = {connection_mode?: string; vpn?: {state: string; route_ready: boolean; reference_num: number}; ssh_connected?: boolean; ui_sessions?: number; mcp_sessions?: number; active_transfers?: number; browser_sessions?: number}
type ConnectionMenu = {profile: ConnectionProfile; x: number; y: number}

const vpnStateLabels: Record<string, string> = {
  disconnected: '未连接',
  not_required: '无需隧道',
  preparing: '正在准备',
  dialing: '正在建立隧道',
  connected: '已连接',
  reconnecting: '正在重连',
  disconnecting: '正在断开',
  failed: '连接异常',
}

export default function App() {
  const [profiles, setProfiles] = useState<ConnectionProfile[]>([])
  const [selectedID, setSelectedID] = useState('')
  const [tabs, setTabs] = useState<TerminalTab[]>([])
  const [activeTab, setActiveTab] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [transferMode, setTransferMode] = useState<TransferMode | null>(null)
  const [editing, setEditing] = useState<ConnectionProfile | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('准备就绪')
  const [status, setStatus] = useState<StatusValue>({})
  const [mcp, setMCP] = useState<MCPState>({enabled: false, address: '', port: 38765})
  const [mcpPort, setMCPPort] = useState(38765)
  const [mcpToken, setMCPToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [connectionMenu, setConnectionMenu] = useState<ConnectionMenu | null>(null)
  const [browserProfile, setBrowserProfile] = useState<ConnectionProfile | null>(null)
  const [confirmation, setConfirmation] = useState<ConfirmOptions | null>(null)
  const confirmationResolver = useRef<((accepted: boolean) => void) | null>(null)

  const confirmAction = useCallback((options: ConfirmOptions) => new Promise<boolean>(resolve => {
    confirmationResolver.current?.(false)
    confirmationResolver.current = resolve
    setConfirmation(options)
  }), [])

  const resolveConfirmation = useCallback((accepted: boolean) => {
    const resolve = confirmationResolver.current
    confirmationResolver.current = null
    setConfirmation(null)
    resolve?.(accepted)
  }, [])

  const selected = profiles.find(value => value.id === selectedID) || null
  const selectedUsesTunnel = selected ? usesIsolatedTunnel(selected) : true
  const vpnState = status.vpn?.state || 'disconnected'
  const vpnStateLabel = vpnStateLabels[vpnState] || vpnState
  const activeTasks = (status.active_transfers || 0) + (status.browser_sessions || 0)
  const groups = useMemo(() => {
    const result = new Map<string, ConnectionProfile[]>()
    profiles.forEach(profile => {
      const name = profile.group || '实验室'
      result.set(name, [...(result.get(name) || []), profile])
    })
    return [...result.entries()]
  }, [profiles])

  const refreshProfiles = async () => {
    try {
      const values = (await ListProfiles()) as ConnectionProfile[]
      setProfiles(values || [])
      setSelectedID(current => current || values?.[0]?.id || '')
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  const refreshMCP = async () => {
    try {
      const value = (await MCPStatus()) as MCPState
      setMCP(value)
      if (value.port) setMCPPort(value.port)
      if (value.enabled) setMCPToken(await MCPAccessToken())
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  useEffect(() => {
    void refreshProfiles()
    void refreshMCP()
    const cancelClosed = EventsOn('terminal:closed', (event: {session_id: string; reason: string}) => {
      setTabs(current => current.map(tab => tab.id === event.session_id ? {...tab, closed: true, reason: event.reason} : tab))
    })
    const cancelMCP = EventsOn('mcp:status', (value: MCPState) => setMCP(value))
    return () => { cancelClosed(); cancelMCP() }
  }, [])

  useEffect(() => {
    if (!selectedID) {
      setStatus({})
      return
    }
    const refresh = () => void ConnectionStatus(selectedID).then(value => setStatus(value as StatusValue)).catch(() => {})
    refresh()
    const timer = window.setInterval(refresh, 3000)
    return () => window.clearInterval(timer)
  }, [selectedID])

  const save = async (request: SaveProfileRequest) => {
    try {
      await SaveProfile(generatedApp.SaveProfileRequest.createFrom(request))
      setDialogOpen(false)
      setEditing(null)
      setNotice('连接配置已保存，敏感凭据由系统安全存储保护')
      await refreshProfiles()
    } catch (error) {
      throw new Error(parseAppError(error).message)
    }
  }

  const testTunnel = async (request: TestConnectionRequest): Promise<ConnectionTestResult> => {
    return await TestTunnelConnection(generatedApp.TestConnectionRequest.createFrom(request)) as ConnectionTestResult
  }

  const testSSH = async (request: TestConnectionRequest): Promise<ConnectionTestResult> => {
    return await TestSSHConnection(generatedApp.TestConnectionRequest.createFrom(request)) as ConnectionTestResult
  }

  const runWithTrustConfirmation = async <T,>(profile: ConnectionProfile, operation: () => Promise<T>): Promise<T> => {
    try {
      return await operation()
    } catch (error) {
      const value = parseAppError(error)
      if (value.code === 'TUNNEL_CERT_UNKNOWN' && value.details?.fingerprint) {
		  const accepted = await confirmAction({
          title: '确认隔离隧道服务器证书',
          message: `服务器：${String(value.details.address || profile.vpn.server_address)}\n指纹：${String(value.details.fingerprint)}\n\n请与管理员提供的指纹核对一致后再信任。`,
          confirmLabel: '信任并继续',
        })
        if (accepted) {
          await AcceptTunnelCertificate(profile.id, String(value.details.fingerprint))
          await refreshProfiles()
          return runWithTrustConfirmation(profile, operation)
        }
      }
      if (value.code === 'SSH_HOST_KEY_UNKNOWN' && value.details?.fingerprint) {
        const accepted = await confirmAction({
          title: '确认 SSH 主机指纹',
          message: `服务器：${String(value.details.address || profile.ssh.server_address)}\n类型：${String(value.details.key_type || '')}\n指纹：${String(value.details.fingerprint)}\n\n请与管理员提供的指纹核对一致后再信任。`,
          confirmLabel: '信任并继续',
        })
        if (accepted) {
          await AcceptHostKey(profile.id, String(value.details.fingerprint))
          return runWithTrustConfirmation(profile, operation)
        }
      }
      throw error
    }
  }

  const connect = async (profile: ConnectionProfile) => {
    if (busy) return
    setBusy(true)
    setSelectedID(profile.id)
    setNotice(`正在连接 ${profile.display_name}…`)
    try {
      const sessionID = await runWithTrustConfirmation(profile, () => ConnectAndOpenTerminal(profile.id, 120, 30))
      setTabs(current => [...current, {id: sessionID, profileId: profile.id, name: profile.display_name, closed: false}])
      setActiveTab(sessionID)
      setNotice(`${profile.display_name} 已连接`)
    } catch (error) {
      const value = parseAppError(error)
      setNotice(`${value.stage ? `[${value.stage}] ` : ''}${value.message}`)
    } finally {
      setBusy(false)
    }
  }

  const startUpload = async (request: UploadRequest): Promise<UploadProgress> => {
    const profile = profiles.find(value => value.id === request.profile_id)
    if (!profile) throw new Error('连接配置不存在')
    try {
      setNotice(`正在为 ${profile.display_name} 准备上传…`)
      const value = await runWithTrustConfirmation(profile, () => StartUpload(request)) as UploadProgress
      setNotice(`已开始向 ${profile.display_name} 上传`)
      return value
    } catch (error) {
      const value = parseAppError(error)
      setNotice(value.message)
      throw error
    }
  }

  const listRemote = async (directory: string): Promise<RemoteDirectory> => {
    if (!selected) throw new Error('连接配置不存在')
    try {
      return await runWithTrustConfirmation(selected, () => ListRemoteDirectory(selected.id, directory)) as RemoteDirectory
    } catch (error) {
      setNotice(parseAppError(error).message)
      throw error
    }
  }

  const startDownload = async (request: DownloadRequest): Promise<DownloadProgress> => {
    const profile = profiles.find(value => value.id === request.profile_id)
    if (!profile) throw new Error('连接配置不存在')
    try {
      setNotice(`正在为 ${profile.display_name} 准备下载…`)
      const value = await runWithTrustConfirmation(profile, () => StartDownload(request)) as DownloadProgress
      setNotice(`已开始从 ${profile.display_name} 下载`)
      return value
    } catch (error) {
      setNotice(parseAppError(error).message)
      throw error
    }
  }

  const closeTab = async (sessionID: string) => {
    try { await CloseTerminal(sessionID) } catch { /* 已关闭的会话可以直接移除标签。 */ }
    setTabs(current => current.filter(tab => tab.id !== sessionID))
    setActiveTab(current => current === sessionID ? (tabs.find(tab => tab.id !== sessionID)?.id || '') : current)
  }

  const deleteProfile = async (profile: ConnectionProfile) => {
    if (!await confirmAction({
      title: `删除连接“${profile.display_name}”`,
      message: '关联的系统安全凭据也会一并删除，此操作无法撤销。',
      confirmLabel: '删除连接',
      danger: true,
    })) return
    try {
      await DeleteProfile(profile.id, true)
      setSelectedID('')
      setNotice(`已删除连接“${profile.display_name}”及其关联凭据`)
      await refreshProfiles()
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  const disconnect = async (profile: ConnectionProfile) => {
    try {
      await DisconnectProfile(profile.id, false)
        setNotice(`${profile.display_name} 的连接已断开`)
    } catch (error) {
      const value = parseAppError(error)
      if (value.code === 'VPN_BUSY' && await confirmAction({
        title: '连接仍在使用中',
        message: `${value.message}\n\n是否关闭全部会话、文件传输和网页访问并强制断开？`,
        confirmLabel: '强制断开',
        danger: true,
      })) {
        await DisconnectProfile(profile.id, true)
        setNotice(`${profile.display_name} 的全部会话与连接已断开`)
      } else setNotice(value.message)
    }
  }

  const openBrowser = async (profile: ConnectionProfile, targetURL: string) => {
    try {
      setNotice(`正在通过 ${profile.display_name} 打开网页访问…`)
      await runWithTrustConfirmation(profile, () => OpenBrowserResource(profile.id, targetURL))
      setNotice(`已在浏览器中打开 ${targetURL}`)
      setStatus(await ConnectionStatus(profile.id) as StatusValue)
    } catch (error) {
      const value = parseAppError(error)
      setNotice(value.message)
      throw new Error(value.message)
    }
  }

  const closeBrowser = async (profile: ConnectionProfile) => {
    try {
      await CloseBrowserAccess(profile.id)
      setNotice(`${profile.display_name} 的网页访问代理已关闭`)
      setStatus(await ConnectionStatus(profile.id) as StatusValue)
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  const showConnectionMenu = (event: React.MouseEvent, profile: ConnectionProfile) => {
    event.preventDefault()
    setSelectedID(profile.id)
    setConnectionMenu({
      profile,
      x: Math.max(8, Math.min(event.clientX, window.innerWidth - 224)),
	  y: Math.max(8, Math.min(event.clientY, window.innerHeight - 320)),
    })
  }

  const toggleMCP = async () => {
    try {
      if (mcp.enabled) {
        await StopMCP()
        setMCPToken('')
        setNotice('MCP 已关闭；图形 SSH 会话保持运行')
      } else {
        const value = await StartMCP(mcpPort) as MCPState
        setMCP(value)
        setMCPToken(await MCPAccessToken())
        setNotice('MCP 仅监听 127.0.0.1')
      }
      await refreshMCP()
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  const copyMCPConfig = async () => {
    try {
      const config = await MCPClientConfig()
      await CopyText(config)
      setNotice('MCP 客户端配置已复制；剪贴板内容不会写入日志')
    } catch (error) { setNotice(parseAppError(error).message) }
  }

  const exportMCPAIGuide = async () => {
    if (!await confirmAction({
      title: '导出 AI 终端操作手册',
      message: '导出的 Markdown 将包含当前 MCP 地址和 Bearer Token，可让本机 AI 客户端直接连接并操作已授权终端。\n\n该文件等同于访问凭据，请勿上传到公开聊天、Git 或发送给无关人员。',
      confirmLabel: '继续导出',
    })) return
    try {
      const path = await ExportMCPAIGuide()
      setNotice(path ? `AI 终端操作手册已导出：${path}` : '已取消导出 AI 终端操作手册')
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  const regenerateToken = async () => {
    if (!await confirmAction({
      title: '重新生成 MCP 令牌',
      message: '重新生成后旧令牌会立即失效，所有使用旧令牌的客户端都需要更新配置。',
      confirmLabel: '重新生成',
      danger: true,
    })) return
    try {
      const token = await RegenerateMCPToken()
      setMCPToken(token)
      setNotice('MCP 令牌已重新生成')
    } catch (error) { setNotice(parseAppError(error).message) }
  }

  const clearSecret = async (profileID: string, kind: 'vpn_psk' | 'vpn_password' | 'ssh_password' | 'ssh_private_key') => {
    if (!await confirmAction({
      title: kind === 'ssh_private_key' ? '清除已保存的 SSH 私钥' : '清除已保存的密码',
      message: '清除后，下次连接前必须重新选择或输入凭据并保存。',
      confirmLabel: '清除凭据',
      danger: true,
    })) return
    try {
      await ClearSavedCredential(profileID, kind)
      setNotice('已从系统安全凭据存储清除凭据')
    } catch (error) {
      setNotice(parseAppError(error).message)
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><div className="brand-mark">LR</div><div><strong>LabRemote</strong><span>安全远程工作台</span></div></div>
        <div className="workspace-context">
          <strong>{selected ? selected.display_name : '远程工作区'}</strong>
          <span>{selected ? `${selected.group || '默认分组'} · ${selected.ssh.server_address}:${selected.ssh.port}` : '管理实验室连接、终端与文件'}</span>
        </div>
        <nav className="toolbar" aria-label="工作区操作">
          <button disabled={!selected} onClick={() => selected && setBrowserProfile(selected)}><span>◎</span>网页访问</button>
          <button className="toolbar-primary" disabled={!selected} onClick={() => setTransferMode('upload')}><span>⇅</span>文件传输</button>
        </nav>
        <div className="mcp-toggle">
          <span className={`status-dot ${mcp.enabled ? 'online' : ''}`} />
          <span><strong>MCP 服务</strong><small>{mcp.enabled ? '运行中' : '已关闭'}</small></span>
          <button className={`switch ${mcp.enabled ? 'on' : ''}`} onClick={toggleMCP} aria-label="切换 MCP"><b /></button>
        </div>
      </header>

      <section className="workspace">
        <aside className="sidebar">
          <div className="connection-panel-header">
            <div className="connection-panel-title"><span>连接配置</span><em>{profiles.length}</em></div>
            <div className="profile-actions" role="toolbar" aria-label="连接配置管理">
              <button className="profile-add" onClick={() => { setEditing(null); setDialogOpen(true) }}><span>＋</span>新建</button>
              <button disabled={!selected} onClick={() => { setEditing(selected); setDialogOpen(true) }}>编辑</button>
              <button className="profile-delete" disabled={!selected} onClick={() => selected && void deleteProfile(selected)}>删除</button>
            </div>
          </div>
          <div className="connection-tree">
            {groups.map(([group, values]) => (
              <div className="tree-group" key={group}>
                <div className="group-title"><span>⌄</span>{group}<em>{values.length}</em></div>
                {values.map(profile => (
                  <button key={profile.id} title="双击连接，右键查看更多操作" className={`profile-row ${selectedID === profile.id ? 'selected' : ''}`} onClick={() => setSelectedID(profile.id)} onDoubleClick={() => void connect(profile)} onContextMenu={event => showConnectionMenu(event, profile)}>
                    <span className={`server-icon ${selectedID === profile.id && (usesIsolatedTunnel(profile) ? vpnState === 'connected' : Boolean(status.ssh_connected)) ? 'online' : ''}`}>›_</span>
                    <span><strong>{profile.display_name}</strong><small>{profile.ssh.server_address}:{profile.ssh.port}</small></span>
                    <span className="profile-badges"><b className="connection-mode-badge" title={usesIsolatedTunnel(profile) ? '隔离隧道 + SSH' : '仅 SSH 直接连接'}>{usesIsolatedTunnel(profile) ? '隧道' : 'SSH'}</b>{profile.mcp_policy.enabled_for_profile && <b className="mcp-badge" title="已允许 MCP 访问">MCP</b>}</span>
                  </button>
                ))}
              </div>
            ))}
            {profiles.length === 0 && <div className="empty-list"><span>＋</span><strong>尚未添加连接</strong><small>创建连接后即可使用终端、文件传输和网页访问。</small><button onClick={() => { setEditing(null); setDialogOpen(true) }}>新建连接</button></div>}
          </div>

          <div className="connection-actions">
            <button className="sidebar-connect" disabled={!selected || busy} onClick={() => selected && void connect(selected)}><span>▶</span>{busy ? '正在连接…' : '连接'}</button>
            <button disabled={!selected} onClick={() => selected && void disconnect(selected)}><span>■</span>断开</button>
          </div>

          <div className="mcp-panel">
            <div className="panel-heading"><span>本地 MCP</span><em className={mcp.enabled ? 'enabled' : ''}>{mcp.enabled ? '运行中' : '已关闭'}</em></div>
            <label className="port-field">端口<input type="number" min={1024} max={65535} disabled={mcp.enabled} value={mcpPort} onChange={event => setMCPPort(Number(event.target.value))} /></label>
            {!mcp.enabled && <p className="mcp-note">服务仅监听 127.0.0.1，开启后仍需为连接单独授权。</p>}
            {mcp.enabled && <>
              <code>{mcp.address}</code>
              <div className="token-line"><input readOnly type={showToken ? 'text' : 'password'} value={mcpToken} aria-label="MCP 访问令牌"/><button onClick={() => setShowToken(value => !value)}>{showToken ? '隐藏' : '显示'}</button></div>
              <button className="wide-action" onClick={copyMCPConfig}>复制 MCP 配置</button>
              <button className="wide-action guide" title="导出包含当前 MCP 令牌、工具说明和 AI 操作规范的 Markdown" onClick={exportMCPAIGuide}>导出 AI 终端操作手册</button>
              <button className="wide-action ghost" onClick={regenerateToken}>重新生成令牌</button>
            </>}
          </div>
        </aside>

        <section className="terminal-area">
          <div className={`tabs ${tabs.length === 0 ? 'empty' : ''}`}>
            {tabs.length === 0 && <span className="tabbar-label">终端会话</span>}
            {tabs.map(tab => (
              <button key={tab.id} className={`tab ${activeTab === tab.id ? 'active' : ''}`} onClick={() => setActiveTab(tab.id)}>
                <span className={`tab-state ${tab.closed ? 'closed' : ''}`} />{tab.name}
                <i onClick={event => { event.stopPropagation(); void closeTab(tab.id) }}>×</i>
              </button>
            ))}
            {selected && <button className="new-tab" title="打开新的终端会话" onClick={() => connect(selected)}><span>＋</span>新建终端</button>}
          </div>
          <div className="terminal-stack">
            {tabs.map(tab => <TerminalView key={tab.id} tab={tab} active={activeTab === tab.id} onReconnect={profileID => { const profile = profiles.find(value => value.id === profileID); if (profile) void connect(profile) }} />)}
            {tabs.length === 0 && <div className="terminal-empty">
              <div className="terminal-empty-card">
                <span className="empty-eyebrow">SECURE REMOTE ACCESS</span>
                <div className="prompt-glyph">&gt;_</div>
                <h1>{selected ? `连接到 ${selected.display_name}` : '开始使用 LabRemote'}</h1>
                <p>{selected ? (selectedUsesTunnel ? '建立进程内隔离隧道，并通过已验证的 SSH 主机打开终端。不会创建系统 VPN、网卡或路由。' : '直接连接已验证的 SSH 主机。网页访问将继续通过 SSH 转发到远端主机可访问的端口。') : '请先在左侧新建连接。配置和凭据将分别安全保存。'}</p>
                <div className="empty-actions">
                  {selected ? <>
                    <button className="button primary" onClick={() => connect(selected)}>连接并打开终端</button>
                    <button className="button secondary" onClick={() => setBrowserProfile(selected)}>网页访问</button>
                  </> : <button className="button primary" onClick={() => { setEditing(null); setDialogOpen(true) }}>新建第一个连接</button>}
                </div>
              </div>
              <div className="security-strip">
                <span><b>01</b><strong>凭据隔离</strong><small>系统安全凭据存储</small></span>
                <span><b>02</b><strong>身份验证</strong><small>证书与 SSH 指纹固定</small></span>
                <span><b>03</b><strong>默认最小权限</strong><small>MCP 默认关闭并逐连接授权</small></span>
              </div>
            </div>}
          </div>
        </section>
      </section>

      <footer className="statusbar">
        <span title={selectedUsesTunnel ? '用户态隔离隧道状态' : '该配置直接连接 SSH，不建立隔离隧道'}><b className={`mini-dot ${selectedUsesTunnel ? (vpnState === 'connected' ? 'online' : '') : (status.ssh_connected ? 'online' : '')}`} />{selectedUsesTunnel ? `隧道 ${vpnStateLabel}` : '方式 仅 SSH'}</span>
        <span title="SSH 控制连接状态"><b className={`mini-dot ${status.ssh_connected ? 'online' : ''}`} />SSH {status.ssh_connected ? '已连接' : '未连接'}</span>
        <span>会话 {(status.ui_sessions || 0) + (status.mcp_sessions || 0)}</span>
        <span>活动任务 {activeTasks}</span>
        <span className="status-message" aria-live="polite"><b>i</b>{notice}</span>
        <span className={`mcp-status ${mcp.enabled ? 'enabled' : ''}`}>MCP {mcp.enabled ? `127.0.0.1:${mcp.port}` : '已关闭'}</span>
      </footer>

      {dialogOpen && <ProfileDialog value={editing} onCancel={() => { setDialogOpen(false); setEditing(null) }} onSave={save} onTestTunnel={testTunnel} onTestSSH={testSSH} onSelectSSHPrivateKey={SelectSSHPrivateKey} onClearSecret={clearSecret} />}
      {browserProfile && <BrowserDialog profile={browserProfile} onClose={() => setBrowserProfile(null)} onOpen={targetURL => openBrowser(browserProfile, targetURL)} />}
      {transferMode && selected && <TransferDialog
        profile={selected}
        initialMode={transferMode}
        terminalSessionID={tabs.find(tab => tab.id === activeTab && tab.profileId === selected.id && !tab.closed)?.id}
        onClose={() => setTransferMode(null)}
        onStartUpload={startUpload}
        onStartDownload={startDownload}
        onListRemote={listRemote}
        onNotice={setNotice}
        onConfirm={confirmAction}
      />}
      {connectionMenu && <div className="connection-menu-layer" onMouseDown={() => setConnectionMenu(null)} onContextMenu={event => { event.preventDefault(); setConnectionMenu(null) }}>
        <nav className="connection-menu" style={{left: connectionMenu.x, top: connectionMenu.y}} onMouseDown={event => event.stopPropagation()}>
          <div className="connection-menu-title"><strong>{connectionMenu.profile.display_name}</strong><small>{connectionMenu.profile.ssh.server_address}:{connectionMenu.profile.ssh.port}</small></div>
          <button disabled={busy} onClick={() => { const profile = connectionMenu.profile; setConnectionMenu(null); void connect(profile) }}>▶ 连接并打开终端</button>
          <button onClick={() => { const profile = connectionMenu.profile; setConnectionMenu(null); void disconnect(profile) }}>■ 断开连接</button>
          <i />
          <button onClick={() => { setBrowserProfile(connectionMenu.profile); setConnectionMenu(null) }}>◎ 网页访问…</button>
          <button onClick={() => { const profile = connectionMenu.profile; setConnectionMenu(null); void closeBrowser(profile) }}>× 关闭网页访问</button>
          <button onClick={() => { setTransferMode('upload'); setConnectionMenu(null) }}>⇅ 文件传输</button>
          <i />
          <button onClick={() => { setEditing(connectionMenu.profile); setDialogOpen(true); setConnectionMenu(null) }}>编辑连接</button>
          <button className="danger" onClick={() => { const profile = connectionMenu.profile; setConnectionMenu(null); void deleteProfile(profile) }}>删除连接</button>
        </nav>
      </div>}
      {confirmation && <ConfirmDialog options={confirmation} onResolve={resolveConfirmation} />}
    </main>
  )
}
