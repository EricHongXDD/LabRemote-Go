import {describe, expect, it} from 'vitest'
import {parseAppError} from './errors'

describe('parseAppError', () => {
  it('解析后端结构化错误', () => {
    const value = parseAppError('APPERROR:{"code":"VPN_TIMEOUT","message":"超时","retryable":true}')
    expect(value.code).toBe('VPN_TIMEOUT')
    expect(value.retryable).toBe(true)
  })

  it('保留普通错误消息', () => {
    expect(parseAppError(new Error('失败')).message).toBe('失败')
  })
})
