import type {ConnectionProfile} from '../types'

export function emptyProfile(): ConnectionProfile {
  return {
    id: '',
    display_name: '',
    group: '实验室',
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
      credential_ref: '',
    },
    mcp_policy: {
      enabled_for_profile: false,
      allow_exec: false,
      allow_interactive: false,
      allow_disconnect: false,
    },
    created_at: '0001-01-01T00:00:00Z',
    updated_at: '0001-01-01T00:00:00Z',
  }
}

export function validateProfile(profile: ConnectionProfile, isNew: boolean, secrets: {psk: string; vpnPassword: string; sshPassword: string}): string | null {
	if (!profile.vpn.connection_name.trim() || profile.vpn.connection_name.trim().length > 64) return '连接名称必须为 1-64 个字符'
	if (!profile.vpn.server_address.trim()) return '隧道服务器地址不能为空'
	if ((profile.vpn.server_port || 992) < 1 || (profile.vpn.server_port || 992) > 65535) return '隧道服务器端口必须为 1-65535'
	if (!profile.vpn.username.trim()) return '隧道用户名不能为空'
  if (!profile.ssh.server_address.trim()) return 'SSH 服务器地址不能为空'
  if (!profile.ssh.username.trim()) return 'SSH 用户名不能为空'
  if (profile.ssh.port < 1 || profile.ssh.port > 65535) return 'SSH 端口必须为 1-65535'
	if (isNew && (!secrets.vpnPassword || !secrets.sshPassword)) return '新建连接时隧道密码和 SSH 密码均为必填'
  return null
}
