import {useEffect, useId, useLayoutEffect, useRef, useState} from 'react'
import {createPortal} from 'react-dom'
import type {CSSProperties, KeyboardEvent} from 'react'

type Option = {value: string; label: string}
type Props = {value: string; options: readonly Option[]; onChange: (value: string) => void; label: string; disabled?: boolean}

export default function Select({value, options, onChange, label, disabled = false}: Props) {
  const id = useId()
  const trigger = useRef<HTMLButtonElement>(null)
  const menu = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const selected = Math.max(0, options.findIndex(option => option.value === value))
  const [active, setActive] = useState(selected)
  const [position, setPosition] = useState<CSSProperties>({})

  useLayoutEffect(() => {
    if (!open || !trigger.current) return
    const rect = trigger.current.getBoundingClientRect()
    const below = window.innerHeight - rect.bottom - 14
    const above = rect.top - 14
    const height = Math.min(280, options.length * 42 + 12)
    const upwards = below < height && above > below
    const width = Math.min(rect.width, window.innerWidth - 24)
    setPosition({
      width,
      left: Math.max(12, Math.min(rect.left, window.innerWidth - width - 12)),
      ...(upwards ? {bottom: window.innerHeight - rect.top + 6} : {top: rect.bottom + 6}),
      maxHeight: Math.max(42, Math.min(280, upwards ? above : below)),
    })
  }, [open, options.length])

  useEffect(() => {
    if (!open) return
    const outside = (event: PointerEvent) => {
      const target = event.target as Node
      if (!trigger.current?.contains(target) && !menu.current?.contains(target)) setOpen(false)
    }
    const close = (event: Event) => {
      if (!menu.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside, true)
    window.addEventListener('resize', close)
    window.addEventListener('scroll', close, true)
    return () => {
      document.removeEventListener('pointerdown', outside, true)
      window.removeEventListener('resize', close)
      window.removeEventListener('scroll', close, true)
    }
  }, [open])

  useEffect(() => {
    if (open) menu.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({block: 'nearest'})
  }, [active, open])

  const choose = (index: number) => {
    onChange(options[index].value)
    setOpen(false)
    trigger.current?.focus()
  }

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === 'Tab') { setOpen(false); return }
    if (event.key === 'Escape' && open) {
      event.preventDefault()
      event.stopPropagation()
      setOpen(false)
      return
    }
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault()
      if (!open) { setActive(event.key === 'End' ? options.length - 1 : event.key === 'Home' ? 0 : selected); setOpen(true); return }
      setActive(current => event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length)
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      if (open) choose(active)
      else { setActive(selected); setOpen(true) }
    } else if (event.key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
      const index = options.findIndex(option => option.label.toLocaleLowerCase().startsWith(event.key.toLocaleLowerCase()))
      if (index >= 0) { event.preventDefault(); setActive(index); setOpen(true) }
    }
  }

  return <span className="custom-select">
    <button ref={trigger} type="button" className={`select-trigger ${open ? 'is-open' : ''}`} role="combobox" aria-label={label} aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? id : undefined} aria-activedescendant={open ? `${id}-${active}` : undefined} disabled={disabled || options.length === 0} onKeyDown={onKeyDown} onBlur={() => setOpen(false)} onClick={() => { setActive(selected); setOpen(current => !current) }}>
      <span>{options.find(option => option.value === value)?.label || '请选择'}</span>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="m4 6 4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
    </button>
    {open && createPortal(<div ref={menu} id={id} role="listbox" aria-label={label} className="select-menu" style={position} onMouseDown={event => event.preventDefault()}>
      {options.map((option, index) => <div key={option.value} id={`${id}-${index}`} data-index={index} role="option" aria-selected={option.value === value} className={`select-option ${index === active ? 'is-active' : ''} ${option.value === value ? 'is-selected' : ''}`} onPointerMove={() => setActive(index)} onClick={event => { event.preventDefault(); choose(index) }}>
        <span>{option.label}</span><span className="select-check" aria-hidden="true">{option.value === value ? '✓' : ''}</span>
      </div>)}
    </div>, document.body)}
  </span>
}
