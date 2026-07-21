import {describe, expect, it} from 'vitest'
import {connectionMode, emptyProfile, sshAuthMethod, validateProfile} from './profile'

describe('validateProfile', () => {
  it('新建配置时要求隧道密码和 SSH 密码', () => {
    const value = emptyProfile()
    value.display_name = '实验室'
    value.vpn.server_address = 'vpn.example.com'
    value.vpn.username = 'user'
    value.ssh.server_address = '192.168.190.10'
    value.ssh.username = 'lab'
    expect(validateProfile(value, true, {vpnPassword: 'vpn', sshPassword: '', sshPrivateKeyPath: ''})).toContain('密码')
  })

  it('编辑配置允许密码留空以保留凭据', () => {
    const value = emptyProfile()
    value.id = 'profile'
    value.display_name = '实验室'
    value.vpn.server_address = 'vpn.example.com'
    value.vpn.username = 'user'
    value.ssh.server_address = '192.168.190.10'
    value.ssh.username = 'lab'
    expect(validateProfile(value, false, {vpnPassword: '', sshPassword: '', sshPrivateKeyPath: ''})).toBeNull()
  })

  it('仅 SSH 配置不要求隧道字段或隧道密码', () => {
    const value = emptyProfile()
    value.connection_mode = 'direct_ssh'
    value.display_name = '公网 SSH'
    value.ssh.server_address = 'ssh.example.com'
    value.ssh.username = 'user'
    expect(validateProfile(value, true, {vpnPassword: '', sshPassword: 'ssh', sshPrivateKeyPath: ''})).toBeNull()
  })

  it('旧配置缺少连接方式时默认使用隔离隧道', () => {
    const value = emptyProfile()
    delete value.connection_mode
    expect(connectionMode(value)).toBe('isolated_tunnel')
    delete value.ssh.auth_method
    expect(sshAuthMethod(value)).toBe('password')
  })

  it('私钥认证要求新建连接选择私钥文件且不要求 SSH 密码', () => {
    const value = emptyProfile()
    value.connection_mode = 'direct_ssh'
    value.display_name = '密钥 SSH'
    value.ssh.server_address = 'ssh.example.com'
    value.ssh.username = 'user'
    value.ssh.auth_method = 'private_key'
    expect(validateProfile(value, true, {vpnPassword: '', sshPassword: '', sshPrivateKeyPath: ''})).toContain('私钥')
    expect(validateProfile(value, true, {vpnPassword: '', sshPassword: '', sshPrivateKeyPath: 'C:\\keys\\id_ed25519'})).toBeNull()
  })
})
