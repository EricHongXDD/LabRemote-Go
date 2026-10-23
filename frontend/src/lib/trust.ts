import type {ConfirmOptions} from '../components/ConfirmDialog'
import type {ConnectionProfile} from '../types'
import {parseAppError} from './errors'

type TrustActions = {
  confirm: (options: ConfirmOptions) => Promise<boolean>
  acceptHostKey: (profileID: string, fingerprint: string) => Promise<void>
  acceptTunnelCertificate: (profileID: string, fingerprint: string) => Promise<void>
}

export async function runWithTrustConfirmation<T>(profile: ConnectionProfile, operation: () => Promise<T>, actions: TrustActions): Promise<T> {
  for (;;) {
    try {
      return await operation()
    } catch (error) {
      const value = parseAppError(error)
      if (value.code === 'TUNNEL_CERT_UNKNOWN' && value.details?.fingerprint) {
        const fingerprint = String(value.details.fingerprint)
        const accepted = await actions.confirm({
          title: '确认隔离隧道服务器证书',
          message: `服务器：${String(value.details.address || profile.vpn.server_address)}\n指纹：${fingerprint}\n\n请与管理员提供的指纹核对一致后再信任。`,
          confirmLabel: '信任并继续',
        })
        if (accepted) {
          await actions.acceptTunnelCertificate(profile.id, fingerprint)
          continue
        }
      }
      const changed = value.code === 'SSH_HOST_KEY_CHANGED'
      const fingerprint = changed ? value.details?.actual : value.details?.fingerprint
      if ((changed || value.code === 'SSH_HOST_KEY_UNKNOWN') && fingerprint) {
        const accepted = await actions.confirm({
          title: changed ? 'SSH 主机指纹已变化' : '确认 SSH 主机指纹',
          message: `服务器：${String(value.details?.address || profile.ssh.server_address)}\n类型：${String(value.details?.key_type || '')}\n${changed ? `原指纹：${String(value.details?.expected || '未知')}\n新指纹：${String(fingerprint)}\n\n服务器重装或密钥轮换可能导致变化，也可能存在中间人攻击。连接已阻断；请通过可信渠道与管理员核对新指纹，确认无误后才替换信任。` : `指纹：${String(fingerprint)}\n\n请与管理员提供的指纹核对一致后再信任。`}`,
          confirmLabel: changed ? '信任新指纹并重试' : '信任并继续',
          cancelLabel: changed ? '取消连接' : '取消',
          danger: changed,
        })
        if (accepted) {
          await actions.acceptHostKey(profile.id, String(fingerprint))
          continue
        }
      }
      throw error
    }
  }
}
