import {describe, expect, it} from 'vitest'
import {emptyProfile, validateProfile} from './profile'

describe('validateProfile', () => {
	it('新建配置时要求隧道密码和 SSH 密码', () => {
    const value = emptyProfile()
    value.vpn.connection_name = '实验室'
    value.vpn.server_address = 'vpn.example.com'
    value.vpn.username = 'user'
    value.ssh.server_address = '192.168.190.10'
    value.ssh.username = 'lab'
		expect(validateProfile(value, true, {psk: '', vpnPassword: 'vpn', sshPassword: ''})).toContain('密码')
  })

  it('编辑配置允许密码留空以保留凭据', () => {
    const value = emptyProfile()
    value.id = 'profile'
    value.vpn.connection_name = '实验室'
    value.vpn.server_address = 'vpn.example.com'
    value.vpn.username = 'user'
    value.ssh.server_address = '192.168.190.10'
    value.ssh.username = 'lab'
    expect(validateProfile(value, false, {psk: '', vpnPassword: '', sshPassword: ''})).toBeNull()
  })
})
