import { type ReactNode } from 'react'

export function Badge({ kind, children }: { kind: 'recorded' | 'live' | 'local'; children: ReactNode }) {
  return <span className={`badge badge--${kind}`}>{children}</span>
}
