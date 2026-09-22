import {beforeEach, describe, expect, it, vi} from 'vitest'
import type {ReactElement} from 'react'
import type {ConnectionProfile} from '../types'
import BrowserDialog from './BrowserDialog'

const state = vi.hoisted(() => ({index: 0, setters: Array.from({length: 6}, () => vi.fn())}))
vi.mock('react', async importOriginal => ({
  ...await importOriginal<typeof import('react')>(),
  useEffect: vi.fn(),
  useState: (initial: unknown) => {
    const index = state.index++
    return [index === 0 ? 'http://127.0.0.1:1294' : initial, state.setters[index]]
  },
}))

function find(element: ReactElement<any>, predicate: (element: ReactElement<any>) => boolean): ReactElement<any> | undefined {
  if (predicate(element)) return element
  const children = [element.props.children].flat(Infinity)
  for (const child of children) {
    if (child && typeof child === 'object' && 'props' in child) {
      const match = find(child, predicate)
      if (match) return match
    }
  }
}

describe('网页访问入口', () => {
  beforeEach(() => { state.index = 0; vi.clearAllMocks() })

  it.each([false, true])('启动默认浏览器=%s 时保留完整访问链接', async launch => {
    const link = 'http://127.0.0.1:54321/__labremote_browser__/secret'
    const onOpen = vi.fn().mockResolvedValue(link)
    const onCopy = vi.fn().mockResolvedValue(undefined)
    const onClose = vi.fn()
    const tree = BrowserDialog({profile: {display_name: '测试'} as ConnectionProfile, onOpen, onCopy, onClose})
    if (launch) find(tree, node => node.type === 'form')!.props.onSubmit({preventDefault: vi.fn()})
    else find(tree, node => node.type === 'button' && node.props.children === '复制访问链接')!.props.onClick()
    await vi.waitFor(() => expect(state.setters[1]).toHaveBeenLastCalledWith(false))
    expect(onOpen).toHaveBeenCalledExactlyOnceWith('http://127.0.0.1:1294', launch)
    expect(state.setters[3]).toHaveBeenCalledWith(link)
    expect(onClose).not.toHaveBeenCalled()
    if (launch) expect(onCopy).not.toHaveBeenCalled()
    else expect(onCopy).toHaveBeenCalledExactlyOnceWith(link)
  })

  it('剪贴板失败时保留可手动复制的链接并显示错误', async () => {
    const tree = BrowserDialog({profile: {} as ConnectionProfile, onOpen: vi.fn().mockResolvedValue('access-link'), onCopy: vi.fn().mockRejectedValue(new Error('剪贴板不可用')), onClose: vi.fn()})
    find(tree, node => node.type === 'button' && node.props.children === '复制访问链接')!.props.onClick()
    await vi.waitFor(() => expect(state.setters[2]).toHaveBeenCalledWith('剪贴板不可用'))
    expect(state.setters[3]).toHaveBeenCalledWith('access-link')
  })
})
