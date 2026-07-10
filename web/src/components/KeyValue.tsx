import { Fragment, type ReactNode } from 'react'

export interface KV {
  k: string
  v: ReactNode
  tone?: 'ok' | 'bad'
  /** Marks the value cell for the scramble-in effect (see fx.ts); purely presentational. */
  scramble?: boolean
}

export function KeyValue({ items }: { items: KV[] }) {
  return (
    <div className="kv-grid">
      {items.map((it, i) => (
        <Fragment key={i}>
          <div className="kv__k">{it.k}</div>
          <div
            className={it.tone ? `kv__v kv__v--${it.tone}` : 'kv__v'}
            data-scramble={it.scramble ? '' : undefined}
          >
            {it.v}
          </div>
        </Fragment>
      ))}
    </div>
  )
}
