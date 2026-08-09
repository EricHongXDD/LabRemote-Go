import {useMemo, useState} from 'react'
import type {ConnectionProfile, ImportConnectionsResult} from '../types'

export type ConnectionBundleMode = 'export' | 'import'

type Props = {
  profiles: ConnectionProfile[]
  initialMode: ConnectionBundleMode
  initialSelectedIDs?: string[]
  onClose: () => void
  onExport: (profileIDs: string[], password: string) => Promise<boolean>
  onSelectImportFile: () => Promise<string>
  onImport: (path: string, password: string) => Promise<ImportConnectionsResult>
}

export default function ConnectionBundleDialog({profiles, initialMode, initialSelectedIDs, onClose, onExport, onSelectImportFile, onImport}: Props) {
  const [mode, setMode] = useState<ConnectionBundleMode>(initialMode)
  const [selectedIDs, setSelectedIDs] = useState<string[]>(initialSelectedIDs?.length ? initialSelectedIDs : profiles.map(profile => profile.id))
  const [filePath, setFilePath] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const selectedSet = useMemo(() => new Set(selectedIDs), [selectedIDs])
  const allSelected = profiles.length > 0 && selectedIDs.length === profiles.length

  const changeMode = (nextMode: ConnectionBundleMode) => {
    if (busy || nextMode === mode) return
    setMode(nextMode)
    setPassword('')
    setConfirmation('')
    setError('')
  }

  const toggleProfile = (profileID: string) => {
    setSelectedIDs(current => current.includes(profileID) ? current.filter(id => id !== profileID) : [...current, profileID])
  }

  const chooseFile = async () => {
    setError('')
    try {
      const path = await onSelectImportFile()
      if (path) setFilePath(path)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }

  const submit = async () => {
    setError('')
    if (password.length < 8) {
      setError('密码至少需要 8 个字符')
      return
    }
    if (mode === 'export') {
      if (selectedIDs.length === 0) {
        setError('请至少选择一个要导出的连接')
        return
      }
      if (password !== confirmation) {
        setError('两次输入的密码不一致')
        return
      }
    } else if (!filePath) {
      setError('请选择要导入的 .lrcx 连接包')
      return
    }
    setBusy(true)
    try {
      if (mode === 'export') {
        if (await onExport(selectedIDs, password)) onClose()
      } else {
        await onImport(filePath, password)
        onClose()
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop bundle-backdrop" role="dialog" aria-modal="true" aria-label={mode === 'export' ? '导出连接' : '导入连接'}>
      <section className="bundle-dialog">
        <header className="dialog-titlebar bundle-titlebar">
          <div>
            <span className="eyebrow">PORTABLE CONNECTION BUNDLE</span>
            <h2>{mode === 'export' ? '导出加密连接包' : '导入加密连接包'}</h2>
          </div>
          <button className="icon-button" disabled={busy} onClick={onClose} aria-label="关闭">×</button>
        </header>

        <div className="bundle-tabs" role="tablist" aria-label="导入导出模式">
          <button className={mode === 'export' ? 'active' : ''} disabled={busy || profiles.length === 0} onClick={() => changeMode('export')}>导出连接</button>
          <button className={mode === 'import' ? 'active' : ''} disabled={busy} onClick={() => changeMode('import')}>导入连接</button>
        </div>

        <div className="bundle-body">
          {mode === 'export' ? <>
            <div className="bundle-section-heading">
              <div><strong>选择连接</strong><small>将导出配置、凭据、私钥和已信任的服务器指纹</small></div>
              <button disabled={busy || profiles.length === 0} onClick={() => setSelectedIDs(allSelected ? [] : profiles.map(profile => profile.id))}>{allSelected ? '取消全选' : '全部选择'}</button>
            </div>
            <div className="bundle-profile-list">
              {profiles.map(profile => <label key={profile.id} className="bundle-profile-row">
                <input type="checkbox" disabled={busy} checked={selectedSet.has(profile.id)} onChange={() => toggleProfile(profile.id)} />
                <span className="server-icon">›_</span>
                <span><strong>{profile.display_name}</strong><small>{profile.ssh.server_address}:{profile.ssh.port} · {profile.ssh.auth_method === 'private_key' ? 'SSH 私钥' : 'SSH 密码'}</small></span>
              </label>)}
            </div>
            <div className="bundle-selection-summary">已选择 {selectedIDs.length} / {profiles.length} 个连接</div>
          </> : <>
            <div className="bundle-section-heading"><div><strong>选择连接包</strong><small>支持 LabRemote `.lrcx` 密码加密连接包</small></div></div>
            <div className="bundle-file-picker">
              <input readOnly value={filePath} placeholder="请选择收到的 .lrcx 文件" aria-label="连接包路径" />
              <button disabled={busy} onClick={chooseFile}>浏览…</button>
            </div>
            <div className="bundle-import-note">
              <strong>安全导入策略</strong>
              <span>导入连接会生成新的连接 ID；名称冲突时自动添加“（导入）”，不会覆盖本机已有配置或凭据。</span>
            </div>
          </>}

          <div className="bundle-password-panel">
            <label>连接包密码
              <input autoFocus={mode === 'import' && Boolean(filePath)} disabled={busy} type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} placeholder={mode === 'export' ? '至少 8 个字符' : '输入发送者提供的密码'} />
            </label>
            {mode === 'export' && <label>确认密码
              <input disabled={busy} type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={confirmation} onChange={event => setConfirmation(event.target.value)} placeholder="再次输入密码" onKeyDown={event => { if (event.key === 'Enter') void submit() }} />
            </label>}
            <label className="check bundle-show-password"><input type="checkbox" disabled={busy} checked={showPassword} onChange={event => setShowPassword(event.target.checked)} />显示密码</label>
          </div>

          <div className="bundle-security-note">
            <b>🔒</b>
            <span><strong>Argon2id + AES-256-GCM</strong><small>文件内容经过密码派生密钥加密并带完整性认证。请通过不同渠道发送连接包和密码；忘记密码后无法恢复。</small></span>
          </div>
          {error && <div className="inline-error bundle-error">{error}</div>}
        </div>

        <footer className="profile-dialog-footer">
          <div className="dialog-feedback">{busy ? (mode === 'export' ? '正在收集并加密连接凭据…' : '正在解密并安全写入连接…') : (mode === 'export' ? '全局 MCP Token 不会被导出' : '导入后可在连接列表中检查并测试连接')}</div>
          <div className="dialog-actions">
            <button className="button secondary" disabled={busy} onClick={onClose}>取消</button>
            <button className="button primary" disabled={busy || (mode === 'export' ? selectedIDs.length === 0 : !filePath)} onClick={() => void submit()}>{busy ? '处理中…' : (mode === 'export' ? '选择位置并导出' : '解密并导入')}</button>
          </div>
        </footer>
      </section>
    </div>
  )
}
