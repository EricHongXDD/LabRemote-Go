import {useEffect} from 'react'

export type ConfirmOptions = {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
}

type Props = {
  options: ConfirmOptions
  onResolve: (accepted: boolean) => void
}

export default function ConfirmDialog({options, onResolve}: Props) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        event.stopImmediatePropagation()
        onResolve(false)
      }
    }
    window.addEventListener('keydown', onKeyDown, true)
    return () => window.removeEventListener('keydown', onKeyDown, true)
  }, [onResolve])

  return (
    <div className="modal-backdrop confirm-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onResolve(false) }}>
      <section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message">
        <div className="confirm-icon" aria-hidden="true">{options.danger ? '!' : '?'}</div>
        <div className="confirm-content">
          <span className="eyebrow">LABREMOTE CONFIRMATION</span>
          <h2 id="confirm-title">{options.title}</h2>
          <p id="confirm-message">{options.message}</p>
        </div>
        <div className="confirm-actions">
          <button className="button secondary" autoFocus onClick={() => onResolve(false)}>{options.cancelLabel || '取消'}</button>
          <button className={`button ${options.danger ? 'danger' : 'primary'}`} onClick={() => onResolve(true)}>{options.confirmLabel || '确认'}</button>
        </div>
      </section>
    </div>
  )
}
