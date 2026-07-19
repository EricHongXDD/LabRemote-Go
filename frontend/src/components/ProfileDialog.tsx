import {useEffect, useState} from 'react'
import type {ConnectionProfile, ConnectionTestResult, SaveProfileRequest, TestConnectionRequest} from '../types'
import {emptyProfile, validateProfile} from '../lib/profile'
import {parseAppError} from '../lib/errors'

type Props = {
  value: ConnectionProfile | null
  onCancel: () => void
  onSave: (request: SaveProfileRequest) => Promise<void>
  onTestTunnel: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onTestSSH: (request: TestConnectionRequest) => Promise<ConnectionTestResult>
  onClearSecret: (profileId: string, kind: 'vpn_psk' | 'vpn_password' | 'ssh_password') => Promise<void>
}

type TestKind = 'tunnel' | 'ssh'
type TestFeedback = {state: 'success' | 'error'; message: string}

export default function ProfileDialog({value, onCancel, onSave, onTestTunnel, onTestSSH, onClearSecret}: Props) {
  const [profile, setProfile] = useState<ConnectionProfile>(emptyProfile())
  const [vpnPassword, setVPNPassword] = useState('')
  const [sshPassword, setSSHPassword] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState<TestKind | null>(null)
  const [testFeedback, setTestFeedback] = useState<Partial<Record<TestKind, TestFeedback>>>({})

  useEffect(() => {
    setProfile(value ? structuredClone(value) : emptyProfile())
    setVPNPassword('')
    setSSHPassword('')
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

  const updatePolicy = (key: string, checked: boolean) => {
    setProfile(current => ({...current, mcp_policy: {...current.mcp_policy, [key]: checked}}))
  }

  const normalizedProfile = () => ({...profile, display_name: profile.vpn.connection_name.trim()})

  const testRequest = (): TestConnectionRequest => ({
    profile: normalizedProfile(),
    vpn_password: vpnPassword,
    ssh_password: sshPassword,
  })

  const validateTunnelTest = (): string | null => {
    if (!profile.vpn.connection_name.trim()) return '请先填写连接名称'
    if (!profile.vpn.server_address.trim()) return '请先填写 SoftEther 服务器'
    if (!profile.vpn.username.trim()) return '请先填写隧道用户名'
    if (!value && !vpnPassword) return '请先填写隧道密码'
    return null
  }

  const testConnection = async (kind: TestKind) => {
    const validationError = kind === 'tunnel'
      ? validateTunnelTest()
      : validateProfile(normalizedProfile(), !value, {psk: '', vpnPassword, sshPassword})
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
    const validationError = validateProfile(normalized, !normalized.id, {psk: '', vpnPassword, sshPassword})
    if (validationError) {
      setError(validationError)
      return
    }
    setSaving(true)
    try {
      await onSave({profile: normalized, vpn_pre_shared_key: '', vpn_password: vpnPassword, ssh_password: sshPassword})
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
          <fieldset className="connection-fieldset">
            <legend><span>01</span> 隔离隧道</legend>
            <label>连接名称<input autoFocus maxLength={64} value={profile.vpn.connection_name} onChange={event => updateVPN('connection_name', event.target.value)} /></label>
            <label>SoftEther 服务器<input value={profile.vpn.server_address} onChange={event => updateVPN('server_address', event.target.value)} /></label>
            <div className="form-row two-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.vpn.server_port || 992} onChange={event => updateVPN('server_port', Number(event.target.value))} /></label>
              <label>Virtual Hub（可选）<input value={profile.vpn.hub_name || ''} placeholder="自动发现" onChange={event => updateVPN('hub_name', event.target.value)} /></label>
            </div>
            <label>传输类型<select value={profile.vpn.type || 'softether'} onChange={event => updateVPN('type', event.target.value)}><option value="softether">SoftEther 原生协议（进程内隔离）</option></select></label>
            <div className="form-row two-columns">
              <label>用户名<input value={profile.vpn.username} onChange={event => updateVPN('username', event.target.value)} autoComplete="username" /></label>
              <label>密码<input type="password" value={vpnPassword} placeholder={value ? '留空保留' : '必填'} onChange={event => { setVPNPassword(event.target.value); setTestFeedback({}) }} autoComplete="new-password" />{value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'vpn_password')}>清除已保存密码</button>}</label>
            </div>
            <div className="connection-test-row">
              <button type="button" className="test-connection-button" disabled={Boolean(testing) || saving} onClick={() => void testConnection('tunnel')}>{testing === 'tunnel' ? '正在测试…' : '测试隔离隧道'}</button>
              {renderFeedback('tunnel')}
            </div>
            <p className="form-note">测试在临时用户态网络中完成，不创建 Windows VPN、网卡或系统路由。</p>
          </fieldset>

          <fieldset className="connection-fieldset">
            <legend><span>02</span> SSH 服务器</legend>
            <label>服务器地址<input value={profile.ssh.server_address} onChange={event => updateSSH('server_address', event.target.value)} /></label>
            <div className="form-row three-columns">
              <label>端口<input type="number" min={1} max={65535} value={profile.ssh.port} onChange={event => updateSSH('port', Number(event.target.value))} /></label>
              <label>用户名<input value={profile.ssh.username} onChange={event => updateSSH('username', event.target.value)} autoComplete="username" /></label>
              <label>密码<input type="password" value={sshPassword} placeholder={value ? '留空保留' : '必填'} onChange={event => { setSSHPassword(event.target.value); setTestFeedback(current => ({...current, ssh: undefined})) }} autoComplete="new-password" />{value && <button type="button" className="clear-secret" onClick={() => onClearSecret(value.id, 'ssh_password')}>清除已保存密码</button>}</label>
            </div>
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
                <label className="check"><input type="checkbox" disabled={!profile.mcp_policy.enabled_for_profile} checked={profile.mcp_policy.allow_disconnect} onChange={event => updatePolicy('allow_disconnect', event.target.checked)} />允许断开隔离隧道</label>
              </div>
            </div>
          </fieldset>
        </div>

        <div className="profile-dialog-footer">
          <div className={`dialog-feedback ${error ? 'error' : ''}`} aria-live="polite">{error || '密码仅在本机用于测试和保存，不会写入应用日志。'}</div>
          <div className="dialog-actions">
            <button className="button secondary" disabled={saving || Boolean(testing)} onClick={onCancel}>取消</button>
            <button className="button primary" onClick={submit} disabled={saving || Boolean(testing)}>{saving ? '保存中…' : '保存连接'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
