import { type StageStatus } from '../demoStages'

export function StatusDot({ status }: { status: StageStatus }) {
  const cls = status === 'idle' ? 'dot' : `dot dot--${status}`
  // role="img" (not a per-dot live region) so screen readers do not announce every status change on
  // all twelve-plus dots.
  return <span className={cls} role="img" aria-label={status} />
}
