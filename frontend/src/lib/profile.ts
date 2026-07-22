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
      allow_disconnect: false,
    },
    created_at: '0001-01-01T00:00:00Z',
    updated_at: '0001-01-01T00:00:00Z',
  }
}

export function connectionMode(profile: ConnectionProfile): ConnectionMode {
  return profile.connection_mode === 'direct_ssh' ? 'direct_ssh' : 'isolated_tunnel'
}

export function usesIsolatedTunnel(profile: ConnectionProfile): boolean {
  return connectionMode(profile) === 'isolated_tunnel'
}

export function sshAuthMethod(profile: ConnectionProfile): SSHAuthMethod {
  return profile.ssh.auth_method === 'private_key' ? 'private_key' : 'password'
}

export function validateProfile(profile: ConnectionProfile, isNew: boolean, credentials: {vpnPassword: string; sshPassword: string; sshPrivateKeyPath: string}): string | null {
  if (!profile.display_name.trim() || profile.display_name.trim().length > 64) return '连接名称必须为 1-64 个字符'
  if (usesIsolatedTunnel(profile)) {
    if (!profile.vpn.server_address.trim()) return '隧道服务器地址不能为空'
    if ((profile.vpn.server_port || 992) < 1 || (profile.vpn.server_port || 992) > 65535) return '隧道服务器端口必须为 1-65535'
    if (!profile.vpn.username.trim()) return '隧道用户名不能为空'
  }
  if (!profile.ssh.server_address.trim()) return 'SSH 服务器地址不能为空'
  if (!profile.ssh.username.trim()) return 'SSH 用户名不能为空'
  if (profile.ssh.port < 1 || profile.ssh.port > 65535) return 'SSH 端口必须为 1-65535'
  if (isNew && sshAuthMethod(profile) === 'password' && !credentials.sshPassword) return '新建连接时 SSH 密码为必填'
  if (isNew && sshAuthMethod(profile) === 'private_key' && !credentials.sshPrivateKeyPath.trim()) return '新建连接时必须选择 SSH 私钥文件'
  if (isNew && usesIsolatedTunnel(profile) && !credentials.vpnPassword) return '新建隔离隧道连接时隧道密码为必填'
  return null
}
