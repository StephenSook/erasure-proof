import { Fragment, type ReactNode } from 'react'

export interface KV {
  k: string
  v: ReactNode
  tone?: 'ok' | 'bad'
}

export function KeyValue({ items }: { items: KV[] }) {
  return (
    <div className="kv-grid">
      {items.map((it, i) => (
        <Fragment key={i}>
          <div className="kv__k">{it.k}</div>
          <div className={it.tone ? `kv__v kv__v--${it.tone}` : 'kv__v'}>{it.v}</div>
        </Fragment>
      ))}
    </div>
  )
}
