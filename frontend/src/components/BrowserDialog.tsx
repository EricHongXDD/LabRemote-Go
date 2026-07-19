import {useEffect, useState} from 'react'
import type {ConnectionProfile} from '../types'

type Props = {
  profile: ConnectionProfile
  onClose: () => void
  onOpen: (targetURL: string) => Promise<void>
}

export default function BrowserDialog({profile, onClose, onOpen}: Props) {
  const [targetURL, setTargetURL] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !pending) onClose()
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose, pending])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!targetURL.trim()) {
      setError('请输入目标地址')
      return
    }
    setPending(true)
    setError('')
    try {
      await onOpen(targetURL.trim())
      onClose()
    } catch (value) {
      setError(value instanceof Error ? value.message : '无法打开网页访问')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !pending) onClose() }}>
      <form className="browser-dialog" onSubmit={submit}>
        <div className="dialog-titlebar">
          <div><span className="eyebrow">ISOLATED WEB ACCESS</span><h2>网页访问</h2></div>
          <button type="button" className="icon-button" disabled={pending} onClick={onClose}>×</button>
        </div>
        <div className="browser-dialog-body">
          <div className="browser-profile"><span className="server-icon">›_</span><div><strong>{profile.display_name}</strong><small>流量通过用户态隔离隧道和 SSH 跳转服务器</small></div></div>
          <label>
            目标 URL
            <input
              autoFocus
              value={targetURL}
              onChange={event => setTargetURL(event.target.value)}
              placeholder="例如：192.168.1.2:2512 或 https://intranet.local"
              spellCheck={false}
            />
          </label>
          <p>支持 HTTP 和 HTTPS。未填写协议时自动使用 HTTP；目标域名由远端 SSH 主机解析，可访问该主机能够到达的内网或公网资源。</p>
          {error && <div className="inline-error browser-error">{error}</div>}
        </div>
        <div className="dialog-actions">
          <button type="button" className="button secondary" disabled={pending} onClick={onClose}>取消</button>
          <button type="submit" className="button primary" disabled={pending}>{pending ? '正在建立访问…' : '打开网页'}</button>
        </div>
      </form>
    </div>
  )
}
