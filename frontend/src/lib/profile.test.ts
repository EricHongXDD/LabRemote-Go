import {describe, expect, it} from 'vitest'
import {connectionMode, createProfileCopyDraft, emptyProfile, sshAuthMethod, validateProfile} from './profile'

describe('validateProfile', () => {
  it('新连接默认不向 MCP 开放本地文件上传', () => {
    expect(emptyProfile().mcp_policy.allow_file_upload).toBe(false)
  })

  it('新连接默认不向 MCP 开放文件下载', () => {
    expect(emptyProfile().mcp_policy.allow_file_download).toBe(false)
  })

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

describe('createProfileCopyDraft', () => {
  it('只清空新连接身份和名称，保留全部可编辑配置且不修改来源', () => {
    const source = emptyProfile()
    source.id = 'profile-source'
    source.display_name = '实验室主机'
    source.group = '课题组'
    source.vpn.connection_name = '实验室主机'
    source.vpn.server_address = 'vpn.example.com'
    source.vpn.hub_name = 'LAB'
    source.vpn.server_certificate = 'SHA256:tunnel'
    source.vpn.username = 'vpn-user'
    source.vpn.credential_ref = 'LabRemote/profile-source/vpn-password'
    source.ssh.server_address = '192.168.1.20'
    source.ssh.username = 'ssh-user'
    source.ssh.credential_ref = 'LabRemote/profile-source/ssh-password'
    source.ssh.host_key = 'SHA256:ssh'
    source.mcp_policy = {...source.mcp_policy, enabled_for_profile: true, allow_exec: true}
    source.created_at = '2026-08-01T00:00:00Z'
    source.updated_at = '2026-08-02T00:00:00Z'

    const copy = createProfileCopyDraft(source)

    expect(copy.id).toBe('')
    expect(copy.display_name).toBe('')
    expect(copy.vpn.connection_name).toBe('')
    expect(copy.vpn.credential_ref).toBe('')
    expect(copy.ssh.credential_ref).toBe('')
    expect(copy.created_at).toBe('0001-01-01T00:00:00Z')
    expect(copy.updated_at).toBe('0001-01-01T00:00:00Z')
    expect({...copy, id: source.id, display_name: source.display_name, vpn: {...copy.vpn, connection_name: source.vpn.connection_name, credential_ref: source.vpn.credential_ref}, ssh: {...copy.ssh, credential_ref: source.ssh.credential_ref}, created_at: source.created_at, updated_at: source.updated_at}).toEqual(source)
    expect(source.display_name).toBe('实验室主机')
  })
})
