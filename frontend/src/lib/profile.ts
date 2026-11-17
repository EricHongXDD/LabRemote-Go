import type {ConnectionMode, ConnectionProfile, SSHAuthMethod} from '../types'

export function emptyProfile(): ConnectionProfile {
  return {
    id: '',
    display_name: '',
    group: '实验室',
    connection_mode: 'isolated_tunnel',
    vpn: {
      connection_name: '',
      server_address: '',
      server_port: 992,
      hub_name: '',
      type: 'softether',
      username: '',
      credential_ref: '',
      split_tunnel: true,
    },
    ssh: {
      server_address: '',
      port: 22,
      username: '',
      auth_method: 'password',
      credential_ref: '',
    },
    mcp_policy: {
      enabled_for_profile: false,
      allow_exec: false,
      allow_interactive: false,
      allow_file_upload: false,
      allow_file_download: false,
      allow_browser: false,
      allow_disconnect: false,
    },
    created_at: '0001-01-01T00:00:00Z',
    updated_at: '0001-01-01T00:00:00Z',
  }
}

export function createProfileCopyDraft(source: ConnectionProfile): ConnectionProfile {
  const value = structuredClone(source)
  value.id = ''
  value.display_name = ''
  value.vpn.connection_name = ''
  value.vpn.credential_ref = ''
  value.ssh.credential_ref = ''
  value.created_at = '0001-01-01T00:00:00Z'
  value.updated_at = '0001-01-01T00:00:00Z'
  return value
}

export function connectionMode(profile: ConnectionProfile): ConnectionMode {
  return profile.connection_mode === 'direct_ssh' ? 'direct_ssh' : profile.connection_mode === 'openvpn_ssh' ? 'openvpn_ssh' : profile.connection_mode === 'atrust_ssh' ? 'atrust_ssh' : 'isolated_tunnel'
}

export function usesIsolatedTunnel(profile: ConnectionProfile): boolean {
  return connectionMode(profile) !== 'direct_ssh'
}

export function usesVPN(profile: ConnectionProfile): boolean {
  return connectionMode(profile) !== 'direct_ssh'
}

export function sshAuthMethod(profile: ConnectionProfile): SSHAuthMethod {
  return profile.ssh.auth_method === 'private_key' ? 'private_key' : 'password'
}

export function validateProfile(profile: ConnectionProfile, isNew: boolean, credentials: {vpnPassword: string; sshPassword: string; sshPrivateKeyPath: string}): string | null {
  if (!profile.display_name.trim() || profile.display_name.trim().length > 64) return '连接名称必须为 1-64 个字符'
  if (connectionMode(profile) === 'isolated_tunnel') {
    if (!profile.vpn.server_address.trim()) return '隧道服务器地址不能为空'
    if ((profile.vpn.server_port || 992) < 1 || (profile.vpn.server_port || 992) > 65535) return '隧道服务器端口必须为 1-65535'
    if (!profile.vpn.username.trim()) return '隧道用户名不能为空'
  }
  if (connectionMode(profile) === 'openvpn_ssh') {
    if (!profile.vpn.openvpn_config?.trim()) return '请导入 OpenVPN 配置文件（.ovpn 或 ZIP）'
    if (!profile.vpn.username.trim()) return '请输入 VPN 用户名'
  }
  if (connectionMode(profile) === 'atrust_ssh' && !validATrustAddress(profile.vpn.server_address)) return '请输入有效的 aTrust HTTPS 服务器地址（仅主机名及可选端口）'
  if (!profile.ssh.server_address.trim()) return 'SSH 服务器地址不能为空'
  if (!profile.ssh.username.trim()) return 'SSH 用户名不能为空'
  if (profile.ssh.port < 1 || profile.ssh.port > 65535) return 'SSH 端口必须为 1-65535'
  if (isNew && sshAuthMethod(profile) === 'password' && !credentials.sshPassword) return '新建连接时 SSH 密码为必填'
  if (isNew && sshAuthMethod(profile) === 'private_key' && !credentials.sshPrivateKeyPath.trim()) return '新建连接时必须选择 SSH 私钥文件'
  if (isNew && usesIsolatedTunnel(profile) && connectionMode(profile) !== 'atrust_ssh' && !credentials.vpnPassword) return '新建 VPN 连接时密码为必填'
  return null
}

export function validATrustAddress(value: string): boolean {
  const text = value.trim()
  if (!text || /[\s\\]/.test(text)) return false
  try {
    const url = new URL(text.includes('://') ? text : `https://${text}`)
    return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password && !url.search && !url.hash && (url.pathname === '/' || !url.pathname) && (!url.port || Number(url.port) > 0) && !/[?#]/.test(text)
  } catch { return false }
}

export function connectionModeLabel(profile: ConnectionProfile): string {
  return {isolated_tunnel: '隔离隧道 + SSH', openvpn_ssh: 'OpenVPN 隔离隧道 + SSH', atrust_ssh: 'aTrust 隔离隧道 + SSH', direct_ssh: '仅 SSH 直接连接'}[connectionMode(profile)]
}

export function connectionModeBadge(profile: ConnectionProfile): string {
  return {isolated_tunnel: '隧道', openvpn_ssh: 'OVPN', atrust_ssh: 'aTrust', direct_ssh: 'SSH'}[connectionMode(profile)]
}
