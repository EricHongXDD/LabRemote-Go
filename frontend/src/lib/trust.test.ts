import {describe, expect, it, vi} from 'vitest'
import type {ConnectionProfile} from '../types'
import {runWithTrustConfirmation} from './trust'

const profile = {id: 'profile-a', ssh: {server_address: '192.0.2.10'}, vpn: {server_address: '192.0.2.20'}} as ConnectionProfile
const changed = {code: 'SSH_HOST_KEY_CHANGED', details: {address: '192.0.2.10:22', key_type: 'ssh-ed25519', expected: 'SHA256:old', actual: 'SHA256:new'}}
const failure = (value: unknown) => new Error(`APPERROR:${JSON.stringify(value)}`)
const actions = (accepted = true) => ({
  confirm: vi.fn().mockResolvedValue(accepted),
  acceptHostKey: vi.fn().mockResolvedValue(undefined),
  acceptTunnelCertificate: vi.fn().mockResolvedValue(undefined),
})

describe('主机信任确认流程', () => {
  it('展示新旧指纹，等待人工确认完成后保存并重试原操作', async () => {
    const error = failure(changed)
    const operation = vi.fn().mockRejectedValueOnce(error).mockResolvedValue('session-id')
    const handlers = actions()
    let resolve!: (accepted: boolean) => void
    handlers.confirm.mockImplementation(() => new Promise<boolean>(done => { resolve = done }))
    const result = runWithTrustConfirmation(profile, operation, handlers)
    await vi.waitFor(() => expect(handlers.confirm).toHaveBeenCalledOnce())
    expect(handlers.confirm.mock.calls[0][0]).toMatchObject({
      title: 'SSH 主机指纹已变化', danger: true, confirmLabel: '信任新指纹并重试', cancelLabel: '取消连接',
    })
    const message = handlers.confirm.mock.calls[0][0].message
    for (const text of ['192.0.2.10:22', 'ssh-ed25519', '原指纹：SHA256:old', '新指纹：SHA256:new', '管理员', '中间人攻击']) expect(message).toContain(text)
    expect(handlers.acceptHostKey).not.toHaveBeenCalled()
    expect(operation).toHaveBeenCalledOnce()
    resolve(true)
    await expect(result).resolves.toBe('session-id')
    expect(handlers.acceptHostKey).toHaveBeenCalledExactlyOnceWith(profile.id, 'SHA256:new')
    expect(operation).toHaveBeenCalledTimes(2)
  })

  it('取消时保留阻断，不保存指纹也不重试', async () => {
    const error = failure(changed)
    const operation = vi.fn().mockRejectedValue(error)
    const handlers = actions(false)
    await expect(runWithTrustConfirmation(profile, operation, handlers)).rejects.toBe(error)
    expect(handlers.acceptHostKey).not.toHaveBeenCalled()
    expect(operation).toHaveBeenCalledOnce()
  })

  it('确认过期或保存失败时不继续连接', async () => {
    const operation = vi.fn().mockRejectedValue(failure(changed))
    const handlers = actions()
    const stale = new Error('没有可确认的主机指纹，或指纹已变化')
    handlers.acceptHostKey.mockRejectedValue(stale)
    await expect(runWithTrustConfirmation(profile, operation, handlers)).rejects.toBe(stale)
    expect(operation).toHaveBeenCalledOnce()
  })

  it('依次确认首次隧道证书和首次 SSH 指纹后恢复操作', async () => {
    const operation = vi.fn()
      .mockRejectedValueOnce(failure({code: 'TUNNEL_CERT_UNKNOWN', details: {fingerprint: 'cert'}}))
      .mockRejectedValueOnce(failure({code: 'SSH_HOST_KEY_UNKNOWN', details: {fingerprint: 'host'}}))
      .mockResolvedValue('connected')
    const handlers = actions()
    await expect(runWithTrustConfirmation(profile, operation, handlers)).resolves.toBe('connected')
    expect(handlers.acceptTunnelCertificate).toHaveBeenCalledExactlyOnceWith(profile.id, 'cert')
    expect(handlers.acceptHostKey).toHaveBeenCalledExactlyOnceWith(profile.id, 'host')
    expect(operation).toHaveBeenCalledTimes(3)
  })

  it.each([
    {code: 'SSH_AUTH_FAILED'},
    {code: 'TUNNEL_CERT_CHANGED', details: {actual: 'cert'}},
    {code: 'SSH_HOST_KEY_CHANGED', details: {expected: 'old'}},
  ])('非 SSH 待确认错误或缺少新指纹时保持阻断：$code', async value => {
    const error = failure(value)
    const operation = vi.fn().mockRejectedValue(error)
    const handlers = actions()
    await expect(runWithTrustConfirmation(profile, operation, handlers)).rejects.toBe(error)
    expect(handlers.confirm).not.toHaveBeenCalled()
    expect(handlers.acceptHostKey).not.toHaveBeenCalled()
    expect(operation).toHaveBeenCalledOnce()
  })
})
