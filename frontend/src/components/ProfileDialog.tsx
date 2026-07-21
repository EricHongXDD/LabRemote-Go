import {useEffect, useState} from 'react'
import type {ConnectionMode, ConnectionProfile, ConnectionTestResult, SaveProfileRequest, SSHAuthMethod, TestConnectionRequest} from '../types'
import {connectionMode, emptyProfile, sshAuthMethod, usesIsolatedTunnel, validateProfile} from '../lib/profile'
import {parseAppError} from '../lib/errors'

type Props = {
  value: ConnectionProfile | null
  onCancel: () => void
  onSave: (request: SaveProfileRequest) => Promise<void>
  onTestTunnel: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onTestSSH: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onSelectSSHPrivateKey: () => Promise<string>
  onClearSecret: (profileId: string, kind: 'vpn_psk' | 'vpn_password' | 'ssh_password' | 'ssh_private_key') => Promise<void>
}

type TestKind = 'tunnel' | 'ssh'
type TestFeedback = {state: 'success' | 'error'; message: string}

export default function ProfileDialog({value, onCancel, onSave, onTestTunnel, onTestSSH, onSelectSSHPrivateKey, onClearSecret}: Props) {
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
  const isPrivateKey = sshAuthMethod(profile) === 'private_key'

  useEffect(() => {
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
  }, [value])

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !saving && !testing) onCancel()
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onCancel, saving, testing])

  const updateVPN = (key: string, fieldValue: string | number | boolean) => {
    setProfile(current => ({...current, vpn: {...current.vpn, [key]: fieldValue}}))
    setTestFeedback({})
  }

  const updateSSH = (key: string, fieldValue: string | number) => {
    setProfile(current => ({...current, ssh: {...current.ssh, [key]: fieldValue}}))
    setTestFeedback(current => ({...current, ssh: undefined}))
  }

  const updateConnectionMode = (mode: ConnectionMode) => {
    setProfile(current => ({...current, connection_mode: mode}))
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

  const testRequest = (): TestConnectionRequest => ({
    profile: normalizedProfile(),
    vpn_password: vpnPassword,
    ssh_password: sshPassword,
    ssh_private_key_path: sshPrivateKeyPath,
    ssh_private_key_passphrase: sshPrivateKeyPassphrase,
  })

  const validateTunnelTest = (): string | null => {
    if (!profile.display_name.trim()) return '请先填写连接名称'
    if (!profile.vpn.server_address.trim()) return '请先填写 SoftEther 服务器'
    if (!profile.vpn.username.trim()) return '请先填写隧道用户名'
    if ((!value || !usesIsolatedTunnel(value)) && !vpnPassword) return '请先填写隧道密码'
    return null
  }

  const validateSSHTest = (): string | null => {
    const validation = validateProfile(normalizedProfile(), !value, {vpnPassword, sshPassword, sshPrivateKeyPath})
    if (validation) return validation
    if (isPrivateKey && (!value || sshAuthMethod(value) !== 'private_key') && !sshPrivateKeyPath) return '请先选择 SSH 私钥文件'
    if (!isPrivateKey && (!value || sshAuthMethod(value) !== 'password') && !sshPassword) return '请先填写 SSH 密码'
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
      const address = result.ip_address ? ` · 地址 ${result.ip_address}` : ''
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
    if (isTunnel && (!value || !usesIsolatedTunnel(value)) && !vpnPassword) {
      setError('切换为隔离隧道连接时必须填写隧道密码')
      return
    }
    if (!isPrivateKey && (!value || sshAuthMethod(value) !== 'password') && !sshPassword) {
      setError('切换为 SSH 密码认证时必须填写 SSH 密码')
      return
    }
    if (isPrivateKey && (!value || sshAuthMethod(value) !== 'private_key') && !sshPrivateKeyPath) {
      setError('切换为 SSH 私钥认证时必须选择私钥文件')
      return
    }
    const validationError = validateProfile(normalized, !normalized.id, {vpnPassword, sshPassword, sshPrivateKeyPath})
    if (validationError) {
      setError(validationError)
      return
    }
    setSaving(true)
    try {
      await onSave({
        profile: normalized,
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
    <div className="modal-backdrop profile-backdrop" role="dialog" aria-modal="true" aria-label={value ? '编辑连接' : '新建连接'}>
      <div className="profile-dialog">
        <div className="dialog-titlebar">
          <div>
            <span className="eyebrow">CONNECTION PROFILE</span>
            <h2>{value ? '编辑连接' : '新建连接'}</h2>
          </div>
          <button className="icon-button" disabled={saving || Boolean(testing)} onClick={onCancel} aria-label="关闭">×</button>
        </div>

        <div className="form-columns">
          <div className="connection-mode-bar">
            <label>连接名称<input autoFocus maxLength={64} value={profile.display_name} onChange={event => { setProfile(current => ({...current, display_name: event.target.value})); setTestFeedback({}) }} /></label>
            <label>连接方式<select value={connectionMode(profile)} onChange={event => updateConnectionMode(event.target.value as ConnectionMode)}>
              <option value="isolated_tunnel">隔离隧道 + SSH</option>
              <option value="direct_ssh">仅 SSH（直接连接）</option>
            </select></label>
            <p>{isTunnel ? '先建立进程内 SoftEther 隔离隧道，再连接内网 SSH。' : '直接连接 SSH 服务器；网页访问仍通过 SSH 转发，可访问远端主机的本机或内网端口。'}</p>
          </div>

          {isTunnel && <fieldset className="connection-fieldset">
            <legend><span>01</span> 隔离隧道</legend>
            <label>SoftEther 服务器<input value={profile.vpn.server_address} onChange={event => updateVPN('server_address', event.target.value)} /></label>
            <div className="form-row two-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.vpn.server_port || 992} onChange={event => updateVPN('server_port', Number(event.target.value))} /></label>
              <label>Virtual Hub（可选）<input value={profile.vpn.hub_name || ''} placeholder="自动发现" onChange={event => updateVPN('hub_name', event.target.value)} /></label>
            </div>
            <label>传输类型<select value={profile.vpn.type || 'softether'} onChange={event => updateVPN('type', event.target.value)}><option value="softether">SoftEther 原生协议（进程内隔离）</option></select></label>
            <div className="form-row two-columns">
              <label>用户名<input value={profile.vpn.username} onChange={event => updateVPN('username', event.target.value)} autoComplete="username" /></label>
              <label>密码<input type="password" value={vpnPassword} placeholder={value && usesIsolatedTunnel(value) ? '留空保留' : '必填'} onChange={event => { setVPNPassword(event.target.value); setTestFeedback({}) }} autoComplete="new-password" />{value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'vpn_password')}>清除已保存密码</button>}</label>
            </div>
            <div className="connection-test-row">
              <button type="button" className="test-connection-button" disabled={Boolean(testing) || saving} onClick={() => void testConnection('tunnel')}>{testing === 'tunnel' ? '正在测试…' : '测试隔离隧道'}</button>
              {renderFeedback('tunnel')}
            </div>
            <p className="form-note">测试在临时用户态网络中完成，不创建 Windows VPN、网卡或系统路由。</p>
          </fieldset>}

          <fieldset className={`connection-fieldset ${isTunnel ? '' : 'direct-profile-fieldset'}`}>
            <legend><span>{isTunnel ? '02' : '01'}</span> SSH 服务器</legend>
            <label>服务器地址<input value={profile.ssh.server_address} onChange={event => updateSSH('server_address', event.target.value)} /></label>
            <div className="form-row three-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.ssh.port} onChange={event => updateSSH('port', Number(event.target.value))} /></label>
              <label>用户名<input value={profile.ssh.username} onChange={event => updateSSH('username', event.target.value)} autoComplete="username" /></label>
              <label>认证方式<select value={sshAuthMethod(profile)} onChange={event => updateSSHAuthMethod(event.target.value as SSHAuthMethod)}>
                <option value="password">密码</option>
                <option value="private_key">私钥文件</option>
              </select></label>
            </div>
            {!isPrivateKey && <label>SSH 密码<input type="password" value={sshPassword} placeholder={value && sshAuthMethod(value) === 'password' ? '留空保留' : '必填'} onChange={event => { setSSHPassword(event.target.value); setTestFeedback(current => ({...current, ssh: undefined})) }} autoComplete="new-password" />{value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'ssh_password')}>清除已保存密码</button>}</label>}
            {isPrivateKey && <div className="form-row two-columns ssh-key-fields">
              <label>私钥文件<div className="private-key-picker"><input readOnly value={sshPrivateKeyPath} placeholder={value && sshAuthMethod(value) === 'private_key' ? '留空保留已保存私钥' : '请选择私钥文件'} /><button type="button" disabled={Boolean(testing) || saving} onClick={() => void selectPrivateKey()}>浏览…</button></div>{value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'ssh_private_key')}>清除已保存私钥</button>}</label>
              <label>私钥口令（可选）<input type="password" value={sshPrivateKeyPassphrase} placeholder={value && sshAuthMethod(value) === 'private_key' ? '留空保留；未加密私钥无需填写' : '仅加密私钥需要'} onChange={event => { setSSHPrivateKeyPassphrase(event.target.value); setTestFeedback(current => ({...current, ssh: undefined})) }} autoComplete="new-password" /></label>
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
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_disconnect} onChange={event => updatePolicy('allow_disconnect', event.target.checked)} />允许断开连接</label>
              </div>
            </div>
          </fieldset>
        </div>

        <div className="profile-dialog-footer">
          <div className={`dialog-feedback ${error ? 'error' : ''}`} aria-live="polite">{error || '认证凭据仅在本机用于测试和保存，不会写入应用日志。'}</div>
          <div className="dialog-actions">
            <button className="button secondary" disabled={saving || Boolean(testing)} onClick={onCancel}>取消</button>
            <button className="button primary" onClick={submit} disabled={saving || Boolean(testing)}>{saving ? '保存中…' : '保存连接'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
