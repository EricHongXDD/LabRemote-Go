import {useEffect, useMemo, useRef, useState} from 'react'
import {
  CancelDownload,
  CancelUpload,
  DescribeUploadSelections,
  DownloadStatus,
  SelectDownloadDirectory,
  SelectUploadDirectory,
  SelectUploadFiles,
  TerminalWorkingDirectory,
  UploadStatus,
} from '../../wailsjs/go/main/DesktopApp'
import {EventsOn, OnFileDrop, OnFileDropOff} from '../../wailsjs/runtime/runtime'
import {parseAppError} from '../lib/errors'
import type {
  ConnectionProfile,
  DownloadProgress,
  DownloadRequest,
  RemoteDirectory,
  RemoteEntry,
  UploadProgress,
  UploadRequest,
  UploadSelection,
} from '../types'

export type TransferMode = 'upload' | 'download'

type Props = {
  profile: ConnectionProfile
  initialMode: TransferMode
  terminalSessionID?: string
  onClose: () => void
  onStartUpload: (request: UploadRequest) => Promise<UploadProgress>
  onStartDownload: (request: DownloadRequest) => Promise<DownloadProgress>
  onListRemote: (directory: string) => Promise<RemoteDirectory>
  onNotice: (message: string) => void
}

const uploadActiveStates = new Set(['queued', 'scanning', 'uploading'])
const downloadActiveStates = new Set(['queued', 'scanning', 'downloading'])

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index++
  }
  return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`
}

function progressStateLabel(mode: TransferMode, state?: string): string {
  if (!state) return '尚未开始'
  if (state === 'queued') return '等待开始'
  if (state === 'scanning') return mode === 'upload' ? '正在扫描本地项目' : '正在扫描远端项目'
  if (state === 'uploading') return '正在上传'
  if (state === 'downloading') return '正在下载'
  if (state === 'completed') return mode === 'upload' ? '上传完成' : '下载完成'
  if (state === 'cancelled') return '已取消，可稍后续传'
  return mode === 'upload' ? '上传失败' : '下载失败'
}

export default function TransferDialog({
  profile,
  initialMode,
  terminalSessionID,
  onClose,
  onStartUpload,
  onStartDownload,
  onListRemote,
  onNotice,
}: Props) {
  const [mode, setMode] = useState<TransferMode>(initialMode)
  const [selections, setSelections] = useState<UploadSelection[]>([])
  const [remoteDirectory, setRemoteDirectory] = useState('~')
  const [browserPath, setBrowserPath] = useState('~')
  const [remoteBrowser, setRemoteBrowser] = useState<RemoteDirectory | null>(null)
  const [selectedRemote, setSelectedRemote] = useState<Set<string>>(new Set())
  const [localDirectory, setLocalDirectory] = useState('')
  const [overwrite, setOverwrite] = useState(false)
  const [resume, setResume] = useState(true)
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null)
  const [downloadProgress, setDownloadProgress] = useState<DownloadProgress | null>(null)
  const [selecting, setSelecting] = useState(false)
  const [starting, setStarting] = useState(false)
  const [remoteLoading, setRemoteLoading] = useState(false)
  const [error, setError] = useState('')
	const remoteLoadSequence = useRef(0)

  const uploadActive = Boolean(uploadProgress && uploadActiveStates.has(uploadProgress.state))
  const downloadActive = Boolean(downloadProgress && downloadActiveStates.has(downloadProgress.state))
  const active = uploadActive || downloadActive
  const progress = mode === 'upload' ? uploadProgress : downloadProgress

  const loadRemote = async (directory: string) => {
    if (!directory.trim()) return
		const sequence = ++remoteLoadSequence.current
    setRemoteLoading(true)
    setError('')
    try {
      const value = await onListRemote(directory.trim())
			if (sequence !== remoteLoadSequence.current) return
      setRemoteBrowser(value)
      setBrowserPath(value.path)
      setSelectedRemote(new Set())
    } catch (value) {
			if (sequence !== remoteLoadSequence.current) return
      setError(parseAppError(value).message)
    } finally {
			if (sequence === remoteLoadSequence.current) setRemoteLoading(false)
    }
  }

  useEffect(() => {
    if (!terminalSessionID) return
    void TerminalWorkingDirectory(terminalSessionID).then(value => {
      if (!value) return
      setRemoteDirectory(value)
      setBrowserPath(value)
      if (mode === 'download') void loadRemote(value)
    }).catch(() => {
      // 不支持 /proc 的远端系统继续使用用户主目录。
    })
  }, [terminalSessionID])

  useEffect(() => {
    if (mode === 'download' && !remoteBrowser && !remoteLoading) void loadRemote(browserPath)
  }, [mode])

  useEffect(() => {
    const cancelUploadEvent = EventsOn('upload:progress', (value: UploadProgress) => {
      if (value.profile_id !== profile.id) return
      setUploadProgress(current => current && current.job_id !== value.job_id ? current : value)
      if (value.state === 'completed') onNotice(`已上传 ${value.files_completed} 个文件到 ${profile.display_name}`)
      if (value.state === 'failed') onNotice(value.error_message || '上传失败')
      if (value.state === 'cancelled') onNotice('上传已取消，分片已保留，可稍后续传')
    })
    const cancelDownloadEvent = EventsOn('download:progress', (value: DownloadProgress) => {
      if (value.profile_id !== profile.id) return
      setDownloadProgress(current => current && current.job_id !== value.job_id ? current : value)
      if (value.state === 'completed') onNotice(`已下载 ${value.files_completed} 个文件`)
      if (value.state === 'failed') onNotice(value.error_message || '下载失败')
      if (value.state === 'cancelled') onNotice('下载已取消，分片已保留，可稍后续传')
    })
    return () => { cancelUploadEvent(); cancelDownloadEvent() }
  }, [onNotice, profile.display_name, profile.id])

  useEffect(() => {
    if (!uploadProgress || !uploadActiveStates.has(uploadProgress.state)) return
    const timer = window.setInterval(() => {
      void UploadStatus(uploadProgress.job_id).then(value => setUploadProgress(value as UploadProgress)).catch(() => {})
    }, 1000)
    return () => window.clearInterval(timer)
  }, [uploadProgress?.job_id, uploadProgress?.state])

  useEffect(() => {
    if (!downloadProgress || !downloadActiveStates.has(downloadProgress.state)) return
    const timer = window.setInterval(() => {
      void DownloadStatus(downloadProgress.job_id).then(value => setDownloadProgress(value as DownloadProgress)).catch(() => {})
    }, 1000)
    return () => window.clearInterval(timer)
  }, [downloadProgress?.job_id, downloadProgress?.state])

  const mergeSelections = (values: UploadSelection[]) => {
    setSelections(current => {
      const result = [...current]
      const known = new Set(current.map(item => item.path.toLocaleLowerCase()))
      values.forEach(item => {
        const key = item.path.toLocaleLowerCase()
        if (item.path && !known.has(key)) {
          known.add(key)
          result.push(item)
        }
      })
      return result
    })
  }

  useEffect(() => {
    if (mode !== 'upload' || active) return
    OnFileDrop((_x, _y, paths) => {
      if (!paths?.length) return
      setSelecting(true)
      setError('')
      void DescribeUploadSelections(paths).then(values => mergeSelections(values as UploadSelection[] || [])).catch(value => {
        setError(parseAppError(value).message)
      }).finally(() => setSelecting(false))
    }, true)
    return () => OnFileDropOff()
  }, [mode, active])

  const selectedBytes = useMemo(
    () => selections.reduce((sum, item) => sum + (item.is_directory ? 0 : item.size), 0),
    [selections],
  )
  const percent = progress?.bytes_total
    ? Math.min(100, Math.round(progress.bytes_transferred * 100 / progress.bytes_total))
    : (progress?.state === 'completed' ? 100 : 0)

  const chooseFiles = async () => {
    setSelecting(true)
    setError('')
    try {
      mergeSelections((await SelectUploadFiles()) as UploadSelection[] || [])
    } catch (value) {
      setError(parseAppError(value).message)
    } finally {
      setSelecting(false)
    }
  }

  const chooseUploadDirectory = async () => {
    setSelecting(true)
    setError('')
    try {
      const value = await SelectUploadDirectory() as UploadSelection
      if (value?.path) mergeSelections([value])
    } catch (value) {
      setError(parseAppError(value).message)
    } finally {
      setSelecting(false)
    }
  }

  const chooseDownloadDirectory = async () => {
    try {
      const value = await SelectDownloadDirectory()
      if (value) setLocalDirectory(value)
    } catch (value) {
      setError(parseAppError(value).message)
    }
  }

  const toggleRemote = (entry: RemoteEntry) => {
    if (entry.is_symlink) return
    setSelectedRemote(current => {
      const result = new Set(current)
      if (result.has(entry.path)) result.delete(entry.path)
      else result.add(entry.path)
      return result
    })
  }

  const startUpload = async () => {
    if (selections.length === 0) return setError('请至少选择一个文件或文件夹')
    if (!remoteDirectory.trim()) return setError('请输入远端目标目录')
    setStarting(true)
    setError('')
    try {
      const value = await onStartUpload({
        profile_id: profile.id,
        local_paths: selections.map(item => item.path),
        remote_directory: remoteDirectory.trim(),
        overwrite,
        resume,
      })
      setUploadProgress(current => current?.job_id === value.job_id ? current : value)
    } catch (value) {
      setError(parseAppError(value).message)
    } finally {
      setStarting(false)
    }
  }

  const startDownload = async () => {
    if (selectedRemote.size === 0) return setError('请至少选择一个远端文件或文件夹')
    if (!localDirectory.trim()) return setError('请选择本地保存目录')
    setStarting(true)
    setError('')
    try {
      const value = await onStartDownload({
        profile_id: profile.id,
        remote_paths: [...selectedRemote],
        local_directory: localDirectory,
        overwrite,
        resume,
      })
      setDownloadProgress(current => current?.job_id === value.job_id ? current : value)
    } catch (value) {
      setError(parseAppError(value).message)
    } finally {
      setStarting(false)
    }
  }

  const cancel = async () => {
    if (!progress || !window.confirm('确定取消当前传输吗？已完成的安全分片会保留，稍后可继续。')) return
    try {
      if (mode === 'upload') await CancelUpload(progress.job_id)
      else await CancelDownload(progress.job_id)
    } catch (value) {
      setError(parseAppError(value).message)
    }
  }

  const close = async () => {
    if (active && progress) {
      if (!window.confirm('文件传输仍在进行。是否取消传输并关闭窗口？')) return
      try {
        if (mode === 'upload') await CancelUpload(progress.job_id)
        else await CancelDownload(progress.job_id)
      } catch { /* 任务可能已在此时结束。 */ }
    }
    onClose()
  }

  return (
    <div className="modal-backdrop">
      <section className="upload-dialog transfer-dialog" role="dialog" aria-modal="true" aria-label="文件传输">
        <header className="dialog-titlebar transfer-titlebar">
          <div><span className="eyebrow">SFTP OVER ISOLATED SSH</span><h2>{profile.display_name} · 文件传输</h2></div>
          <div className="transfer-tabs">
            <button className={mode === 'upload' ? 'active' : ''} disabled={active} onClick={() => setMode('upload')}>⇧ 上传</button>
            <button className={mode === 'download' ? 'active' : ''} disabled={active} onClick={() => setMode('download')}>⇩ 下载</button>
          </div>
          <button className="icon-button" onClick={() => void close()} aria-label="关闭">×</button>
        </header>

        {mode === 'upload' ? (
          <div className="upload-body">
            <section className="upload-source-panel">
              <div className="upload-section-title"><span>本地项目</span><em>{selections.length}</em></div>
              <div className="upload-picker-actions">
                <button disabled={active || selecting} onClick={() => void chooseFiles()}>＋ 选择文件</button>
                <button disabled={active || selecting} onClick={() => void chooseUploadDirectory()}>▣ 选择文件夹</button>
              </div>
              <div className="upload-list file-drop-zone">
                {selections.map(item => (
                  <div className="upload-item" key={item.path} title={item.path}>
                    <span className="upload-item-icon">{item.is_directory ? '▣' : '▤'}</span>
                    <span><strong>{item.name}</strong><small>{item.is_directory ? '文件夹（将递归上传）' : formatBytes(item.size)}</small></span>
                    <button disabled={active} onClick={() => setSelections(current => current.filter(value => value.path !== item.path))} aria-label={`移除 ${item.name}`}>×</button>
                  </div>
                ))}
                {selections.length === 0 && <div className="upload-list-empty"><span>拖拽文件或文件夹到这里<br/>也可混合选择多个项目</span></div>}
              </div>
              <div className="upload-selection-summary">已选 {selections.length} 项 · 已知大小 {formatBytes(selectedBytes)} · 文件夹结构与空目录会保留</div>
            </section>

            <section className="upload-target-panel">
              <label>远端目标目录
                <input disabled={active} value={remoteDirectory} onChange={event => setRemoteDirectory(event.target.value)} placeholder="~ 或 /home/user/path" />
              </label>
              <small>{terminalSessionID ? '默认读取当前活动终端所在目录；也可手动修改。' : '未找到当前连接的活动终端，默认使用远端用户主目录。'}</small>
              <TransferOptions active={active} overwrite={overwrite} resume={resume} setOverwrite={setOverwrite} setResume={setResume} direction="upload" />
              <ProgressCard mode={mode} progress={progress} percent={percent} />
            </section>
          </div>
        ) : (
          <div className="upload-body download-body">
            <section className="upload-source-panel remote-browser-panel">
              <div className="upload-section-title"><span>远端项目</span><em>{selectedRemote.size}</em></div>
              <div className="remote-pathbar">
                <button disabled={active || remoteLoading || !remoteBrowser} onClick={() => void loadRemote(remoteBrowser?.parent || '~')} title="上一级">↑</button>
                <input disabled={active} value={browserPath} onChange={event => setBrowserPath(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') void loadRemote(browserPath) }} />
                <button disabled={active || remoteLoading} onClick={() => void loadRemote(browserPath)}>{remoteLoading ? '读取中' : '转到'}</button>
              </div>
              <div className="remote-list">
                {remoteBrowser?.entries.map(entry => (
                  <div className={`remote-item ${entry.is_symlink ? 'disabled' : ''}`} key={entry.path} onDoubleClick={() => entry.is_directory && !entry.is_symlink && void loadRemote(entry.path)} title={entry.path}>
                    <input type="checkbox" disabled={active || entry.is_symlink} checked={selectedRemote.has(entry.path)} onChange={() => toggleRemote(entry)} onDoubleClick={event => event.stopPropagation()} />
                    <span className="upload-item-icon">{entry.is_symlink ? '↗' : entry.is_directory ? '▣' : '▤'}</span>
                    <span><strong>{entry.name}</strong><small>{entry.is_symlink ? '符号链接（不跟随）' : entry.is_directory ? '文件夹 · 双击进入' : formatBytes(entry.size)}</small></span>
                    {entry.is_directory && !entry.is_symlink && <button disabled={active} onClick={() => void loadRemote(entry.path)}>打开</button>}
                  </div>
                ))}
                {!remoteLoading && remoteBrowser?.entries.length === 0 && <div className="upload-list-empty">此远端目录为空</div>}
                {remoteLoading && <div className="upload-list-empty">正在读取远端目录…</div>}
              </div>
              <div className="upload-selection-summary">当前位置：{remoteBrowser?.path || browserPath} · 可选择文件和文件夹递归下载</div>
            </section>

            <section className="upload-target-panel">
              <label>本地保存目录
                <span className="local-path-picker"><input readOnly value={localDirectory} placeholder="请选择本地文件夹" /><button disabled={active} onClick={() => void chooseDownloadDirectory()}>浏览…</button></span>
              </label>
              <small>下载先写入同目录分片，校验完成后再改名；空目录和修改时间会保留。</small>
              <TransferOptions active={active} overwrite={overwrite} resume={resume} setOverwrite={setOverwrite} setResume={setResume} direction="download" />
              <ProgressCard mode={mode} progress={progress} percent={percent} />
            </section>
          </div>
        )}

        {error && <div className="inline-error">{error}</div>}
        <footer className="dialog-actions">
          <button className="button secondary" onClick={() => void close()}>{active ? '关闭并取消' : '关闭'}</button>
          {active
            ? <button className="button danger" onClick={() => void cancel()}>取消{mode === 'upload' ? '上传' : '下载'}</button>
            : <button className="button primary" disabled={starting || (mode === 'upload' ? selections.length === 0 : selectedRemote.size === 0)} onClick={() => void (mode === 'upload' ? startUpload() : startDownload())}>{starting ? '正在连接…' : `开始${mode === 'upload' ? '上传' : '下载'}`}</button>}
        </footer>
      </section>
    </div>
  )
}

function TransferOptions({active, overwrite, resume, setOverwrite, setResume, direction}: {
  active: boolean
  overwrite: boolean
  resume: boolean
  setOverwrite: (value: boolean) => void
  setResume: (value: boolean) => void
  direction: TransferMode
}) {
  return <>
    <label className="check upload-overwrite"><input type="checkbox" disabled={active} checked={resume} onChange={event => setResume(event.target.checked)} />启用断点续传</label>
    <label className="check upload-overwrite"><input type="checkbox" disabled={active} checked={overwrite} onChange={event => setOverwrite(event.target.checked)} />覆盖{direction === 'upload' ? '远端' : '本地'}同名文件</label>
    <div className="upload-safety-note">并行传输最多同时处理 3 个文件，单个大文件使用并发 SFTP 请求；取消或网络中断会保留已校正的安全分片。</div>
  </>
}

function ProgressCard({mode, progress, percent}: {mode: TransferMode; progress: UploadProgress | DownloadProgress | null; percent: number}) {
  return <div className={`upload-progress-card ${progress?.state || ''}`}>
    <div className="upload-progress-heading"><strong>{progressStateLabel(mode, progress?.state)}</strong><em>{percent}%</em></div>
    <div className={`upload-progress-track ${progress?.state === 'scanning' ? 'indeterminate' : ''}`}><i style={{width: `${percent}%`}} /></div>
    <div className="upload-progress-stats">
      <span>文件 {progress?.files_completed || 0}/{progress?.files_total || 0}</span>
      <span>目录 {progress?.directories_completed || 0}/{progress?.directories_total || 0}</span>
      <span>{formatBytes(progress?.bytes_transferred || 0)} / {formatBytes(progress?.bytes_total || 0)}</span>
    </div>
    <div className="transfer-acceleration">
      <span>并发文件 {progress?.concurrent_files || 0}</span>
      {(progress?.bytes_resumed || 0) > 0 && <span>已续传 {formatBytes(progress?.bytes_resumed || 0)}</span>}
    </div>
    <div className="upload-current-item" title={progress?.current_item}>{progress?.current_item || `等待选择并开始${mode === 'upload' ? '上传' : '下载'}`}</div>
    {progress?.error_message && <div className="upload-error">{progress.error_message}</div>}
  </div>
}
