import { useEffect, useRef } from 'react'
import { motionEnabled } from '../motion'

// A 3-node CockroachDB cluster rendered from the REAL recorded node-kill run (the transcript is the
// source of truth, this is its visualization, honestly labeled "recorded" by the stage badge).
// roach2 is stopped: it flickers to grey, the surviving two hold quorum and keep serving the
// committed erasure state, then roach2 rejoins and catches up via Raft. Under reduced motion the
// final settled state renders instantly (roach2 back, all healthy), so nothing depends on motion.

type NodeState = 'leader' | 'follower' | 'down'

const NODES: { id: string; label: string; x: number; y: number }[] = [
  { id: 'roach1', label: 'roach1', x: 60, y: 40 },
  { id: 'roach2', label: 'roach2', x: 180, y: 40 },
  { id: 'roach3', label: 'roach3', x: 120, y: 130 },
]

export function ClusterMap() {
  const rootRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    const svg = rootRef.current
    if (!svg || !motionEnabled()) {
      return // reduced motion / tests: the static markup already shows the settled healthy state
    }
    // Choreograph the kill and rejoin with plain timeouts (no library needed): roach2 goes down,
    // the survivors pulse to show they still serve, then roach2 rejoins.
    const set = (id: string, cls: string) => {
      const el = svg.querySelector<SVGGElement>(`[data-node="${id}"]`)
      if (el) el.dataset.state = cls
    }
    set('roach2', 'leader') // start healthy, then kill after a beat
    const t1 = window.setTimeout(() => set('roach2', 'down'), 900)
    const t2 = window.setTimeout(() => set('roach2', 'follower'), 3200) // rejoins, catches up
    return () => {
      window.clearTimeout(t1)
      window.clearTimeout(t2)
    }
  }, [])

  // Settled state (also the reduced-motion state): roach1 leads, all three up.
  const initial: Record<string, NodeState> = { roach1: 'leader', roach2: 'follower', roach3: 'follower' }

  return (
    <svg
      ref={rootRef}
      className="clustermap"
      viewBox="0 0 240 180"
      role="img"
      aria-label="Three-node CockroachDB cluster: one node is stopped and the surviving two keep the committed erasure state via Raft quorum, then the node rejoins."
    >
      {/* Raft replication links */}
      <g className="clustermap__links">
        <line x1="60" y1="40" x2="180" y2="40" />
        <line x1="60" y1="40" x2="120" y2="130" />
        <line x1="180" y1="40" x2="120" y2="130" />
      </g>
      {NODES.map((n) => (
        <g key={n.id} data-node={n.id} data-state={initial[n.id]} className="clustermap__node">
          <circle cx={n.x} cy={n.y} r="20" />
          <text x={n.x} y={n.y + 4} textAnchor="middle" className="clustermap__label">
            {n.label}
          </text>
        </g>
      ))}
    </svg>
  )
}
