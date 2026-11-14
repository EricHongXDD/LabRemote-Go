import {useEffect, useState} from 'react'
import {parseAppError} from '../lib/errors'

export type OTPChallenge = {id: string; profile_id: string; profile_name: string; username: string; prompt: string}

export default function OpenVPNOTPDialog({challenge, onSubmit}: {challenge: OTPChallenge; onSubmit: (id: string, code: string) => Promise<void>}) {
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const submit = async (value: string) => {
    if (submitting) return
    setSubmitting(true)
    setError('')
    try { await onSubmit(challenge.id, value); setCode('') }
    catch (reason) { setError(parseAppError(reason).message); setSubmitting(false) }
  }
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        event.stopImmediatePropagation()
        void submit('')
      }
    }
    window.addEventListener('keydown', onKeyDown, true)
    return () => window.removeEventListener('keydown', onKeyDown, true)
  }, [challenge.id, submitting])
  return <div className="modal-backdrop openvpn-otp-backdrop">
    <form className="profile-dialog openvpn-otp-dialog" role="dialog" aria-modal="true" aria-labelledby="openvpn-otp-title" onSubmit={event => { event.preventDefault(); void submit(code) }}>
      <div className="dialog-titlebar"><div><span className="eyebrow">OPENVPN</span><h2 id="openvpn-otp-title">输入动态验证码</h2></div></div>
      <div className="openvpn-otp-body">
        <p>{challenge.profile_name} · {challenge.username}</p>
        <p>{challenge.prompt}</p>
        <p>请从 VPN 服务提供方指定的验证器或令牌平台获取当前 6 位验证码，并确认使用的令牌与 VPN 账号一致。</p>
        <label>OTP / TOTP 验证码<input autoFocus inputMode="numeric" autoComplete="one-time-code" aria-label="6 位动态验证码" maxLength={6} pattern="[0-9]{6}" required value={code} onChange={event => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} /></label>
        <p className="form-note">验证码仅用于本次认证；过期后请重新连接并使用最新验证码。</p>
        {error && <p role="alert">{error}</p>}
      </div>
      <div className="confirm-actions"><button type="button" className="button secondary" disabled={submitting} onClick={() => void submit('')}>取消连接</button><button type="submit" className="button primary" disabled={submitting || !/^\d{6}$/.test(code)}>{submitting ? '正在发送…' : '发送验证码'}</button></div>
    </form>
  </div>
}
