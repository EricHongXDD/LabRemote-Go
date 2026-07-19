import type {AppErrorValue} from '../types'

export function parseAppError(error: unknown): AppErrorValue {
  const text = error instanceof Error ? error.message : String(error)
  const marker = 'APPERROR:'
  const start = text.indexOf(marker)
  if (start >= 0) {
    try {
      return JSON.parse(text.slice(start + marker.length)) as AppErrorValue
    } catch {
      // 解析失败时退回通用错误，避免界面丢失原始信息。
    }
  }
  return {code: 'UNEXPECTED', message: text || '发生未知错误', retryable: false}
}
