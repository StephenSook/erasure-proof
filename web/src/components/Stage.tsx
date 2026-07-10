import { type CSSProperties, type ReactNode } from 'react'
import { type StageMeta, type StageStatus } from '../demoStages'
import { StatusDot } from './StatusDot'

type StyleWithVars = CSSProperties & Record<`--${string}`, string>

export function Stage({
  meta,
  status,
  children,
}: {
  meta: StageMeta
  status: StageStatus
  children: ReactNode
}) {
  const style: StyleWithVars = { '--hue': meta.hue }
  return (
    <section className="stage" style={style} id={`stage-${meta.id}`}>
      <div className="stage__bar" />
      <div className="stage__head">
        <div>
          <div className="stage__eyebrow">{meta.eyebrow}</div>
          <h2 className="stage__title">
            {meta.n}. {meta.title}
          </h2>
        </div>
        <StatusDot status={status} />
      </div>
      <div className="stage__body">
        <p className="stage__desc">{meta.desc}</p>
        {children}
      </div>
    </section>
  )
}
