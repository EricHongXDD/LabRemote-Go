export const ctrlCDoublePressWindowMs = 400

export type CtrlCAction = 'copy' | 'interrupt' | 'ignore'

export function resolveCtrlCAction(lastPressAt: number | null, currentTime: number, hasSelection: boolean, windowMs = ctrlCDoublePressWindowMs): CtrlCAction {
  if (lastPressAt !== null && currentTime >= lastPressAt && currentTime - lastPressAt <= windowMs) return 'interrupt'
  return hasSelection ? 'copy' : 'ignore'
}
