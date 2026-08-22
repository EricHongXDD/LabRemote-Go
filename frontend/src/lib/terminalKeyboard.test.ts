import {describe, expect, it} from 'vitest'
import {resolveCtrlCAction} from './terminalKeyboard'

describe('终端 Ctrl+C 行为', () => {
  it('单次按下且有选中内容时复制', () => {
    expect(resolveCtrlCAction(null, 1000, true)).toBe('copy')
  })

  it('单次按下没有选中内容时不向远端发送字符', () => {
    expect(resolveCtrlCAction(null, 1000, false)).toBe('ignore')
  })

  it('短时间连续两次按下时发送中断动作', () => {
    expect(resolveCtrlCAction(1000, 1400, true)).toBe('interrupt')
    expect(resolveCtrlCAction(1000, 1400, false)).toBe('interrupt')
  })

  it('超过双击窗口后恢复为单次复制行为', () => {
    expect(resolveCtrlCAction(1000, 1401, true)).toBe('copy')
  })
})
