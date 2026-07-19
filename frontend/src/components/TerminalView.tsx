import {useEffect, useRef, useState} from 'react'
import {Terminal} from '@xterm/xterm'
import {FitAddon} from '@xterm/addon-fit'
import {SearchAddon} from '@xterm/addon-search'
import {WebLinksAddon} from '@xterm/addon-web-links'
import {EventsOn} from '../../wailsjs/runtime/runtime'
import {ResizeTerminal, WriteTerminal} from '../../wailsjs/go/main/DesktopApp'
import type {TerminalTab} from '../types'

type Props = {
  tab: TerminalTab
  active: boolean
  onReconnect: (profileId: string) => void
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value)
  const output = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) output[index] = binary.charCodeAt(index)
  return output
}

export default function TerminalView({tab, active, onReconnect}: Props) {
  const container = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const searchRef = useRef<SearchAddon | null>(null)
  const [searchVisible, setSearchVisible] = useState(false)
  const [search, setSearch] = useState('')

  useEffect(() => {
    if (!container.current) return
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: 'Cascadia Mono, Consolas, Microsoft YaHei UI, monospace',
      fontSize: 14,
      lineHeight: 1.18,
      scrollback: 10000,
      theme: {
        background: '#070d18', foreground: '#d8e6f4', cursor: '#4ee1a0', selectionBackground: '#245f7a88',
        black: '#0b1020', red: '#ff6b7a', green: '#4ee1a0', yellow: '#f4cc67', blue: '#5aa9ff', magenta: '#c792ea', cyan: '#4dd9e6', white: '#d8e6f4',
        brightBlack: '#526179', brightRed: '#ff8a96', brightGreen: '#72f5b7', brightYellow: '#ffe195', brightBlue: '#88c2ff', brightMagenta: '#dfafff', brightCyan: '#87edf5', brightWhite: '#ffffff',
      },
    })
    const fit = new FitAddon()
    const searchAddon = new SearchAddon()
    terminal.loadAddon(fit)
    terminal.loadAddon(searchAddon)
    terminal.loadAddon(new WebLinksAddon())
    terminal.open(container.current)
    fit.fit()
    terminal.focus()
    terminalRef.current = terminal
    fitRef.current = fit
    searchRef.current = searchAddon

    const dataDisposable = terminal.onData(data => void WriteTerminal(tab.id, data))
    const resizeDisposable = terminal.onResize(({cols, rows}) => void ResizeTerminal(tab.id, cols, rows))
    terminal.attachCustomKeyEventHandler(event => {
      if (event.type !== 'keydown') return true
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 'c') {
        if (terminal.hasSelection()) void navigator.clipboard.writeText(terminal.getSelection())
        return false
      }
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 'v') {
        void navigator.clipboard.readText().then(text => WriteTerminal(tab.id, text))
        return false
      }
      if (event.ctrlKey && event.key.toLowerCase() === 'f') {
        setSearchVisible(true)
        return false
      }
      return true
    })
    const cancelData = EventsOn('terminal:data', (chunk: {session_id: string; data_base64: string}) => {
      if (chunk.session_id === tab.id) terminal.write(decodeBase64(chunk.data_base64))
    })
    const resizeObserver = new ResizeObserver(() => {
      fit.fit()
    })
    resizeObserver.observe(container.current)
    return () => {
      resizeObserver.disconnect()
      cancelData()
      dataDisposable.dispose()
      resizeDisposable.dispose()
      terminal.dispose()
      terminalRef.current = null
    }
  }, [tab.id])

  useEffect(() => {
    if (active) {
      requestAnimationFrame(() => {
        fitRef.current?.fit()
        terminalRef.current?.focus()
      })
    }
  }, [active])

  return (
    <div className={`terminal-view ${active ? 'active' : ''}`}>
      {searchVisible && (
        <div className="terminal-search">
          <input autoFocus value={search} onChange={event => { setSearch(event.target.value); searchRef.current?.findNext(event.target.value) }} onKeyDown={event => event.key === 'Enter' && searchRef.current?.findNext(search)} placeholder="搜索终端输出" />
          <button onClick={() => searchRef.current?.findPrevious(search)}>↑</button>
          <button onClick={() => searchRef.current?.findNext(search)}>↓</button>
          <button onClick={() => setSearchVisible(false)}>×</button>
        </div>
      )}
      <div ref={container} className="terminal-canvas" onContextMenu={event => {
        event.preventDefault()
        const selected = terminalRef.current?.getSelection()
        if (selected) void navigator.clipboard.writeText(selected)
        else void navigator.clipboard.readText().then(text => WriteTerminal(tab.id, text))
      }} />
      {tab.closed && (
        <div className="terminal-disconnected">
          <strong>会话已断开</strong>
          <span>{tab.reason || '远程连接已结束'}</span>
          <button className="button primary" onClick={() => onReconnect(tab.profileId)}>重新连接</button>
        </div>
      )}
    </div>
  )
}
