import {useEffect, useRef, useState} from 'react'
import type {ConnectionMode, ConnectionProfile, ConnectionTestResult, SaveProfileRequest, SSHAuthMethod, TestConnectionRequest} from '../types'
import {connectionMode, emptyProfile, sshAuthMethod, usesVPN, usesIsolatedTunnel, validATrustAddress, validateProfile} from '../lib/profile'
import {parseAppError} from '../lib/errors'
import Select from './Select'

type Props = {
  value: ConnectionProfile | null
  copySourceProfileID: string
  onCancel: () => void
  onSave: (request: SaveProfileRequest) => Promise<void>
  onTestTunnel: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onTestSSH: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onCloseTestSession: (sessionID: string) => Promise<void>
  onImportOpenVPNConfig: () => Promise<string>
  onSelectSSHPrivateKey: () => Promise<string>
  onClearSecret: (profileId: string, kind: 'vpn_psk' | 'vpn_password' | 'ssh_password' | 'ssh_private_key' | 'atrust_session') => Promise<void>
}

type TestKind = 'tunnel' | 'ssh'
type TestFeedback = {state: 'success' | 'error'; message: string}

export default function ProfileDialog({value, copySourceProfileID, onCancel, onSave, onTestTunnel, onTestSSH, onCloseTestSession, onImportOpenVPNConfig, onSelectSSHPrivateKey, onClearSecret}: Props) {
  const testSessionID = useRef(crypto.randomUUID())
  const resetTestSession = () => {
    const previous = testSessionID.current
    testSessionID.current = crypto.randomUUID()
    void onCloseTestSession(previous).catch(() => {})
  }
  useEffect(() => () => { void onCloseTestSession(testSessionID.current).catch(() => {}) }, [onCloseTestSession])
  const [profile, setProfile] = useState<ConnectionProfile>(emptyProfile())
  const [vpnPassword, setVPNPassword] = useState('')
  const [sshPassword, setSSHPassword] = useState('')
  const [sshPrivateKeyPath, setSSHPrivateKeyPath] = useState('')
  const [sshPrivateKeyPassphrase, setSSHPrivateKeyPassphrase] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState<TestKind | null>(null)
  const [testFeedback, setTestFeedback] = useState<Partial<Record<TestKind, TestFeedback>>>({})
  const isTunnel = usesIsolatedTunnel(profile)
  const isATrust = connectionMode(profile) === 'atrust_ssh'
  const hasNetworkStep = isTunnel || isATrust
  const isOpenVPN = connectionMode(profile) === 'openvpn_ssh'
  const isPrivateKey = sshAuthMethod(profile) === 'private_key'
  const isCopy = Boolean(copySourceProfileID)
  const isExisting = Boolean(value?.id) && !isCopy
  const canReuseTunnelCredential = Boolean(value && usesVPN(value) && connectionMode(value) === connectionMode(profile) && isTunnel)
  const canReuseSSHPassword = Boolean(value && sshAuthMethod(value) === 'password' && !isPrivateKey)
  const canReuseSSHPrivateKey = Boolean(value && sshAuthMethod(value) === 'private_key' && isPrivateKey)

  useEffect(() => {
    resetTestSession()
    const next = value ? structuredClone(value) : emptyProfile()
    next.connection_mode = connectionMode(next)
    next.ssh.auth_method = sshAuthMethod(next)
    setProfile(next)
    setVPNPassword('')
    setSSHPassword('')
    setSSHPrivateKeyPath('')
    setSSHPrivateKeyPassphrase('')
    setError('')
    setTesting(null)
    setTestFeedback({})
  }, [value, copySourceProfileID])

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !saving && !testing) onCancel()
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onCancel, saving, testing])

  const updateVPN = (key: string, fieldValue: string | number | boolean) => {
    resetTestSession()
    setProfile(current => ({...current, vpn: {...current.vpn, [key]: fieldValue}}))
    setTestFeedback({})
  }

  const updateSSH = (key: string, fieldValue: string | number) => {
    setProfile(current => ({...current, ssh: {...current.ssh, [key]: fieldValue}}))
    setTestFeedback(current => ({...current, ssh: undefined}))
  }

  const updateConnectionMode = (mode: ConnectionMode) => {
    resetTestSession()
    setProfile(current => ({...current, connection_mode: mode, vpn: {...current.vpn, type: mode === 'openvpn_ssh' ? 'openvpn' : mode === 'atrust_ssh' ? 'atrust' : 'softether'}}))
    setTestFeedback({})
    setError('')
  }

  const updateSSHAuthMethod = (method: SSHAuthMethod) => {
    setProfile(current => ({...current, ssh: {...current.ssh, auth_method: method}}))
    setTestFeedback(current => ({...current, ssh: undefined}))
    setError('')
  }

  const selectPrivateKey = async () => {
    try {
      const path = await onSelectSSHPrivateKey()
      if (path) {
        setSSHPrivateKeyPath(path)
        setTestFeedback(current => ({...current, ssh: undefined}))
      }
    } catch (reason) {
      setError(parseAppError(reason).message)
    }
  }

  const updatePolicy = (key: string, checked: boolean) => {
    setProfile(current => ({...current, mcp_policy: {...current.mcp_policy, [key]: checked}}))
  }

  const normalizedProfile = (): ConnectionProfile => {
    const displayName = profile.display_name.trim()
    return {
      ...profile,
      display_name: displayName,
      connection_mode: connectionMode(profile),
      vpn: {...profile.vpn, connection_name: isTunnel ? displayName : profile.vpn.connection_name},
      ssh: {...profile.ssh, auth_method: sshAuthMethod(profile)},
    }
  }

  const testRequest = (): TestConnectionRequest => {
    const normalized = normalizedProfile()
    return {
      profile: copySourceProfileID ? {...normalized, id: copySourceProfileID} : normalized,
      test_session_id: testSessionID.current,
      vpn_password: vpnPassword,
      ssh_password: sshPassword,
      ssh_private_key_path: sshPrivateKeyPath,
      ssh_private_key_passphrase: sshPrivateKeyPassphrase,
    }
  }

  const validateTunnelTest = (): string | null => {
    if (!profile.display_name.trim()) return '请先填写连接名称'
    if (isATrust) return validATrustAddress(profile.vpn.server_address) ? null : '请先填写有效的 aTrust HTTPS 服务器地址'
    if (isOpenVPN && !profile.vpn.openvpn_config?.trim()) return '请先导入 OpenVPN 配置'
    if (!isOpenVPN && !profile.vpn.server_address.trim()) return '请先填写 SoftEther 服务器'
    if (!profile.vpn.username.trim()) return '请先填写隧道用户名'
    if (!canReuseTunnelCredential && !vpnPassword) return '请先填写隧道密码'
    return null
  }

  const validateSSHTest = (): string | null => {
    const validation = validateProfile(normalizedProfile(), !value && !copySourceProfileID, {vpnPassword, sshPassword, sshPrivateKeyPath})
    if (validation) return validation
    if (isPrivateKey && !canReuseSSHPrivateKey && !sshPrivateKeyPath) return '请先选择 SSH 私钥文件'
    if (!isPrivateKey && !canReuseSSHPassword && !sshPassword) return '请先填写 SSH 密码'
    return null
  }

  const testConnection = async (kind: TestKind) => {
    const validationError = kind === 'tunnel'
      ? validateTunnelTest()
      : validateSSHTest()
    if (validationError) {
      setTestFeedback(current => ({...current, [kind]: {state: 'error', message: validationError}}))
      return
    }
    setTesting(kind)
    setError('')
    setTestFeedback(current => ({...current, [kind]: undefined}))
    try {
      const result = kind === 'tunnel' ? await onTestTunnel(testRequest()) : await onTestSSH(testRequest())
      const address = result.ip_address ? ` · 本机隧道地址 ${result.ip_address}` : ''
      const duration = result.duration_ms > 0 ? ` · ${(result.duration_ms / 1000).toFixed(1)} 秒` : ''
      setTestFeedback(current => ({...current, [kind]: {state: 'success', message: `${result.message}${address}${duration}`}}))
    } catch (reason) {
      setTestFeedback(current => ({...current, [kind]: {state: 'error', message: parseAppError(reason).message}}))
    } finally {
      setTesting(null)
    }
  }

  const submit = async () => {
    const normalized = normalizedProfile()
    if (isTunnel && !isATrust && !canReuseTunnelCredential && !vpnPassword) {
      setError('请填写 VPN 登录密码')
      return
    }
    if (!isPrivateKey && !canReuseSSHPassword && !sshPassword) {
      setError('切换为 SSH 密码认证时必须填写 SSH 密码')
      return
    }
    if (isPrivateKey && !canReuseSSHPrivateKey && !sshPrivateKeyPath) {
      setError('切换为 SSH 私钥认证时必须选择私钥文件')
      return
    }
    const validationError = validateProfile(normalized, !normalized.id && !copySourceProfileID, {vpnPassword, sshPassword, sshPrivateKeyPath})
    if (validationError) {
      setError(validationError)
      return
    }
    setSaving(true)
    try {
      await onSave({
		test_session_id: testSessionID.current,
        profile: normalized,
        copy_from_profile_id: copySourceProfileID,
        vpn_pre_shared_key: '',
        vpn_password: vpnPassword,
        ssh_password: sshPassword,
        ssh_private_key_path: sshPrivateKeyPath,
        ssh_private_key_passphrase: sshPrivateKeyPassphrase,
      })
    } catch (reason) {
      setError(String(reason))
    } finally {
      setSaving(false)
    }
  }

  const renderFeedback = (kind: TestKind) => {
    const feedback = testFeedback[kind]
    return <span className={`connection-test-feedback ${feedback?.state || ''}`} title={feedback?.message || ''}>{feedback?.message || '测试过程不会保存或修改正式配置'}</span>
  }

  return (
    <div className="modal-backdrop profile-backdrop" role="dialog" aria-modal="true" aria-label={isCopy ? '复制连接' : (isExisting ? '编辑连接' : '新建连接')}>
      <div className="profile-dialog">
        <div className="dialog-titlebar">
          <div>
            <span className="eyebrow">CONNECTION PROFILE</span>
            <h2>{isCopy ? '复制连接' : (isExisting ? '编辑连接' : '新建连接')}</h2>
          </div>
          <button className="icon-button" disabled={saving || Boolean(testing)} onClick={onCancel} aria-label="关闭">×</button>
        </div>

        <div className="form-columns">
          <div className="connection-mode-bar">
            <label>连接名称<input autoFocus maxLength={64} value={profile.display_name} onChange={event => { setProfile(current => ({...current, display_name: event.target.value})); setTestFeedback({}) }} /></label>
            <label>连接方式<Select label="连接方式" value={connectionMode(profile)} onChange={mode => updateConnectionMode(mode as ConnectionMode)} options={[
              {value: 'isolated_tunnel', label: '隔离隧道 + SSH'},
              {value: 'openvpn_ssh', label: 'OpenVPN 隔离隧道 + SSH（OTP）'},
              {value: 'atrust_ssh', label: 'aTrust 隔离隧道 + SSH（网页登录）'},
              {value: 'direct_ssh', label: '仅 SSH（直接连接）'},
            ]} /></label>
            <p>{isATrust ? '在独立网页窗口完成认证，仅为配置的 SSH 目标建立进程内 TCP 通道。' : isOpenVPN ? '导入 OpenVPN 配置，在进程内建立 OpenVPN 隔离隧道，按提示输入验证码，再访问 SSH。' : isTunnel ? '先建立进程内 SoftEther 隔离隧道，再连接内网 SSH。' : '直接连接 SSH 服务器；网页访问仍通过 SSH 转发，可访问远端主机的本机或内网端口。'}</p>
          </div>

          {!isOpenVPN && !isATrust && isTunnel && <fieldset className="connection-fieldset">
            <legend><span>01</span> 隔离隧道</legend>
            <label>SoftEther 服务器<input value={profile.vpn.server_address} onChange={event => updateVPN('server_address', event.target.value)} /></label>
            <div className="form-row two-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.vpn.server_port || 992} onChange={event => updateVPN('server_port', Number(event.target.value))} /></label>
              <label>Virtual Hub（可选）<input value={profile.vpn.hub_name || ''} placeholder="自动发现" onChange={event => updateVPN('hub_name', event.target.value)} /></label>
            </div>
            <label>传输类型<Select label="传输类型" value={profile.vpn.type || 'softether'} onChange={type => updateVPN('type', type)} options={[{value: 'softether', label: 'SoftEther 原生协议（进程内隔离）'}]} /></label>
            <div className="form-row two-columns">
              <label>用户名<input value={profile.vpn.username} onChange={event => updateVPN('username', event.target.value)} autoComplete="username" /></label>
              <label>密码<input type="password" value={vpnPassword} placeholder={canReuseTunnelCredential ? (isCopy ? '留空复制已保存密码' : '留空保留') : '必填'} onChange={event => { resetTestSession(); setVPNPassword(event.target.value); setTestFeedback({}) }} autoComplete="new-password" />{isExisting && value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'vpn_password')}>清除已保存密码</button>}</label>
            </div>
            <div className="connection-test-row">
              <button type="button" className="test-connection-button" disabled={Boolean(testing) || saving} onClick={() => void testConnection('tunnel')}>{testing === 'tunnel' ? '正在测试…' : '测试隔离隧道'}</button>
              {renderFeedback('tunnel')}
            </div>
            <p className="form-note">测试在临时用户态网络中完成，不创建 Windows VPN、网卡或系统路由。</p>
          </fieldset>}

          {isATrust && <fieldset className="connection-fieldset atrust-fieldset">
            <legend><span>01</span> aTrust VPN</legend>
            <label>服务器地址<input value={profile.vpn.server_address} placeholder="https://vpn.example.com" onChange={event => updateVPN('server_address', event.target.value)} spellCheck={false} /></label>
            <div className="atrust-login-steps">
              <p><b>1</b>点击认证或测试 SSH，优先恢复有效会话，需要登录时自动打开独立浏览器窗口。</p>
              <p><b>2</b>在服务提供方页面手动完成登录及验证码认证。</p>
              <p><b>3</b>登录票据保存在系统凭据库，重启后仍可恢复；过期或服务端要求验证时重新登录。</p>
            </div>
            <div className="connection-test-row"><button type="button" className="test-connection-button" disabled={saving || Boolean(testing)} onClick={() => void testConnection('tunnel')}>{testing === 'tunnel' ? '正在认证…' : '认证 aTrust'}</button>{renderFeedback('tunnel')}</div>
            {isExisting && value && <button type="button" className="clear-secret" disabled={saving || Boolean(testing)} onClick={() => void onClearSecret(value.id, 'atrust_session')}>清除 aTrust 登录状态</button>}
            <p className="form-note">协议适配正在验收。使用应用进程内的目标 TCP 通道，不启动 aTrust 客户端、不创建系统 VPN、路由或代理。网页访问与文件传输均沿用 SSH；通道不可用时不会系统直连。</p>
          </fieldset>}

          {isOpenVPN && <fieldset className="connection-fieldset">
            <legend><span>01</span> OpenVPN</legend>
            <label>配置文件（.ovpn / ZIP）<div className="private-key-picker"><input readOnly value={profile.vpn.openvpn_config ? '已导入 OpenVPN 配置（含 CA 与备用服务器）' : ''} placeholder="选择 .ovpn 或包含配置的 ZIP 文件" /><button type="button" disabled={Boolean(testing) || saving} onClick={async () => {
              try { const config = await onImportOpenVPNConfig(); if (config) { updateVPN('openvpn_config', config); setError('') } }
              catch (reason) { setError(parseAppError(reason).message) }
            }}>导入…</button></div></label>
            <div className="form-row two-columns">
              <label>VPN 用户名<input value={profile.vpn.username} onChange={event => updateVPN('username', event.target.value)} autoComplete="username" /></label>
              <label>VPN 密码<input type="password" value={vpnPassword} placeholder={canReuseTunnelCredential ? '留空保留已保存密码' : '必填'} onChange={event => { resetTestSession(); setVPNPassword(event.target.value); setTestFeedback({}) }} autoComplete="new-password" />{isExisting && value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'vpn_password')}>清除已保存密码</button>}</label>
            </div>
            <p className="form-note">连接请求 OTP / TOTP 时会弹窗输入当前 6 位验证码。请从 VPN 服务提供方指定的验证器或令牌平台获取，无需填写令牌密钥。</p>
            <div className="connection-test-row"><button type="button" className="test-connection-button" disabled={Boolean(testing) || saving} onClick={() => void testConnection('tunnel')}>{testing === 'tunnel' ? '正在测试…' : '测试 OpenVPN'}</button>{renderFeedback('tunnel')}</div>
            <p className="form-note">同一窗口中的 VPN 与 SSH 测试复用已认证隧道，调整 SSH 参数或测试失败无需再次输入 OTP。更改 VPN 配置、关闭窗口或空闲 15 分钟后回收测试连接。全程使用进程内隔离网络。</p>
          </fieldset>}

          <fieldset className={`connection-fieldset ${hasNetworkStep ? '' : 'direct-profile-fieldset'}`}>
            <legend><span>{hasNetworkStep ? '02' : '01'}</span> SSH 服务器</legend>
            <label>服务器地址<input value={profile.ssh.server_address} onChange={event => updateSSH('server_address', event.target.value)} /></label>
            <div className="form-row three-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.ssh.port} onChange={event => updateSSH('port', Number(event.target.value))} /></label>
              <label>用户名<input value={profile.ssh.username} onChange={event => updateSSH('username', event.target.value)} autoComplete="username" /></label>
              <label>认证方式<Select label="认证方式" value={sshAuthMethod(profile)} onChange={method => updateSSHAuthMethod(method as SSHAuthMethod)} options={[
                {value: 'password', label: '密码'},
                {value: 'private_key', label: '私钥文件'},
              ]} /></label>
            </div>
            {!isPrivateKey && <label>SSH 密码<input type="password" value={sshPassword} placeholder={canReuseSSHPassword ? (isCopy ? '留空复制已保存密码' : '留空保留') : '必填'} onChange={event => { setSSHPassword(event.target.value); setTestFeedback(current => ({...current, ssh: undefined})) }} autoComplete="new-password" />{isExisting && value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'ssh_password')}>清除已保存密码</button>}</label>}
            {isPrivateKey && <div className="form-row two-columns ssh-key-fields">
              <label>私钥文件<div className="private-key-picker"><input readOnly value={sshPrivateKeyPath} placeholder={canReuseSSHPrivateKey ? (isCopy ? '留空复制已保存私钥' : '留空保留已保存私钥') : '请选择私钥文件'} /><button type="button" disabled={Boolean(testing) || saving} onClick={() => void selectPrivateKey()}>浏览…</button></div>{isExisting && value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'ssh_private_key')}>清除已保存私钥</button>}</label>
              <label>私钥口令（可选）<input type="password" value={sshPrivateKeyPassphrase} placeholder={canReuseSSHPrivateKey ? (isCopy ? '留空复制已保存口令' : '留空保留；未加密私钥无需填写') : '仅加密私钥需要'} onChange={event => { setSSHPrivateKeyPassphrase(event.target.value); setTestFeedback(current => ({...current, ssh: undefined})) }} autoComplete="new-password" /></label>
            </div>}
            <div className="connection-test-row">
              <button type="button" className="test-connection-button" disabled={Boolean(testing) || saving} onClick={() => void testConnection('ssh')}>{testing === 'ssh' ? '正在测试…' : '测试 SSH 服务器'}</button>
              {renderFeedback('ssh')}
            </div>

            <div className="policy-panel">
              <div className="policy-heading">MCP 最小权限</div>
              <div className="policy-grid">
                <label className="check"><input type="checkbox" checked={profile.mcp_policy.enabled_for_profile} onChange={event => updatePolicy('enabled_for_profile', event.target.checked)} />允许 MCP 看到此配置</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_exec} onChange={event => updatePolicy('allow_exec', event.target.checked)} />允许执行非交互命令</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_interactive} onChange={event => updatePolicy('allow_interactive', event.target.checked)} />允许创建交互会话</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_file_upload} onChange={event => updatePolicy('allow_file_upload', event.target.checked)} />允许上传本地文件</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_file_download} onChange={event => updatePolicy('allow_file_download', event.target.checked)} />允许下载文件到本机</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_browser ?? false} onChange={event => updatePolicy('allow_browser', event.target.checked)} />允许获取网页访问链接</label>
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_disconnect} onChange={event => updatePolicy('allow_disconnect', event.target.checked)} />允许断开连接</label>
              </div>
            </div>
          </fieldset>
        </div>

        <div className="profile-dialog-footer">
          <div className={`dialog-feedback ${error ? 'error' : ''}`} aria-live="polite">{error || (isCopy ? '连接名称已清空；留空的凭据会从来源连接安全复制，也可以输入新值覆盖。' : '认证凭据仅在本机用于测试和保存，不会写入应用日志。')}</div>
          <div className="dialog-actions">
            <button className="button secondary" disabled={saving || Boolean(testing)} onClick={onCancel}>取消</button>
            <button className="button primary" onClick={submit} disabled={saving || Boolean(testing)}>{saving ? '保存中…' : (isCopy ? '保存副本' : '保存连接')}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
