import { type CSSProperties } from 'react'
import { Badge } from '../components/Badge'
import { CodeBlock } from '../components/CodeBlock'
import { KeyValue } from '../components/KeyValue'
import { Stage } from '../components/Stage'
import { StatusDot } from '../components/StatusDot'
import { demoMemory } from '../data/demoMemory'
import { STAGES, type StageId, type StageMeta } from '../demoStages'
import { useDemo } from '../useDemo'

type StyleWithVars = CSSProperties & Record<`--${string}`, string>

const short = (s: string | null | undefined, n = 20): string =>
  !s ? '' : s.length > n ? `${s.slice(0, n)}...` : s

const isMock = import.meta.env.VITE_USE_MOCK === '1'

function scrollToStage(id: StageId) {
  document.getElementById(`stage-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

export function DemoConsole() {
  const { state, actions } = useDemo()

  // The action records its own error in state; swallow the rejection so an individual stage click
  // never leaves an unhandled promise rejection on the console.
  const fire = (p: Promise<unknown>) => {
    void p.catch(() => undefined)
  }
  const run: Record<StageId, () => void> = {
    memory: () => fire(actions.runMemory()),
    leak: () => fire(actions.runLeak()),
    envelope: () => fire(actions.runEnvelope()),
    erase: () => fire(actions.runErase()),
    durability: () => fire(actions.runDurability()),
    audit: () => fire(actions.runAudit()),
  }
  const runLabel: Record<StageId, string> = {
    memory: 'Store a memory',
    leak: 'Attempt inversion',
    envelope: 'Inspect the envelope',
    erase: 'Crypto-erase this subject',
    durability: 'Show the recorded node-kill',
    audit: 'Verify retention',
  }

  const busy = Object.values(state.status).some((s) => s === 'running')

  function body(meta: StageMeta) {
    const st = state.status[meta.id]
    const err = state.error[meta.id]
    const runButton = (
      <button
        className={meta.id === 'erase' ? 'btn btn--accent' : 'btn'}
        onClick={run[meta.id]}
        disabled={busy || st === 'running'}
      >
        {st === 'running' ? 'Running...' : runLabel[meta.id]}
      </button>
    )

    return (
      <>
        <div className="stage__actions">
          {runButton}
          {stageBadge(meta.id)}
        </div>
        {err && <div className="note note--error">{err}</div>}
        {stageResult(meta.id)}
      </>
    )
  }

  function stageBadge(id: StageId) {
    if (id === 'memory' || id === 'erase' || id === 'audit') return <Badge kind="live">Live</Badge>
    if (id === 'leak') return <Badge kind="recorded">Recorded golden run</Badge>
    if (id === 'durability') return <Badge kind="local">Local 3-node cluster</Badge>
    return null
  }

  function stageResult(id: StageId) {
    switch (id) {
      case 'memory':
        return (
          <>
            <div className="note">
              Storing: <span className="mono">{demoMemory.text}</span>
            </div>
            {state.memory && (
              <KeyValue
                items={[
                  { k: 'subject_id', v: state.memory.subject_id },
                  { k: 'memory_id', v: state.memory.memory_id },
                  { k: 'content ciphertext', v: `${state.memory.content_len} bytes` },
                  { k: 'embedding ciphertext', v: `${state.memory.embedding_len} bytes` },
                  { k: 'live vector', v: state.memory.embedding_present ? 'present (C-SPANN)' : 'absent', tone: 'ok' },
                  { k: 'subject key fingerprint', v: short(state.memory.key_fingerprint) },
                ]}
              />
            )}
          </>
        )
      case 'leak':
        return (
          state.inversion && (
            <>
              <KeyValue
                items={[
                  { k: 'recovered text', v: <b className="kv__v--bad">{String(state.inversion.recovered_text ?? '')}</b>, tone: 'bad' },
                  { k: 'from sentence', v: String(state.inversion.sentence ?? '') },
                  { k: 'model', v: String(state.inversion.model ?? '') },
                  { k: 'gpu', v: String(state.inversion.gpu ?? '') },
                  { k: 'recorded', v: String(state.inversion.recorded_at ?? '') },
                ]}
              />
              <div className="note">
                {String(state.inversion.disclosure ?? '')} The name is reconstructed from the embedding
                alone, so deleting the row is not enough.
              </div>
            </>
          )
        )
      case 'envelope':
        return (
          state.memory && (
            <>
              <KeyValue
                items={[
                  { k: 'durable content', v: `${state.memory.content_len} bytes ciphertext (AES-256-GCM)` },
                  { k: 'durable embedding', v: `${state.memory.embedding_len} bytes ciphertext` },
                  { k: 'per-row key', v: 'wrapped under the per-subject key' },
                  { k: 'subject key fingerprint', v: short(state.memory.key_fingerprint) || '(destroyed)', tone: state.memory.key_fingerprint ? undefined : 'ok' },
                ]}
              />
              <div className="note">
                Destroying the per-subject key (one row) makes every per-row key permanently
                unwrappable while the ciphertext survives as provable noise.
              </div>
            </>
          )
        )
      case 'erase':
        return (
          <>
            {state.erase && (
              <KeyValue
                items={[
                  { k: 'decision_log seq', v: String(state.erase.result.decision_log_seq) },
                  { k: 'key origin', v: state.erase.result.key_origin },
                  { k: 'kms key', v: short(state.erase.result.kms_key_arn, 32) },
                  { k: 'proof', v: state.erase.proof_ref ?? '(anchoring pending)', tone: 'ok' },
                ]}
              />
            )}
            {state.memoryAfter && (
              <KeyValue
                items={[
                  { k: 'live vector', v: state.memoryAfter.embedding_present ? 'STILL PRESENT' : 'purged to NULL', tone: state.memoryAfter.embedding_present ? 'bad' : 'ok' },
                  { k: 'subject key', v: state.memoryAfter.key_fingerprint ? 'STILL PRESENT' : 'destroyed (row gone)', tone: state.memoryAfter.key_fingerprint ? 'bad' : 'ok' },
                ]}
              />
            )}
            {state.proof && (
              <div className="note">
                Proof record read back:{' '}
                <span className="mono">{state.proof.proof_ref ?? '(anchoring pending)'}</span>
                {state.proof.committed_at ? `, committed ${state.proof.committed_at}` : ''}
              </div>
            )}
          </>
        )
      case 'durability':
        return (
          state.status.durability === 'done' && (
            <>
              <div className="note">
                Recorded on the local 3-node cluster: erase committed, then <span className="mono">docker stop roach2</span>,
                then the committed state was read back from a surviving replica.
              </div>
              <CodeBlock>{RECORDED_NODE_KILL}</CodeBlock>
            </>
          )
        )
      case 'audit':
        return (
          <>
            {state.chain && (
              <KeyValue
                items={[
                  { k: 'hash chain', v: state.chain.intact ? 'intact' : `BROKEN at seq ${String(state.chain.break_at_seq)}`, tone: state.chain.intact ? 'ok' : 'bad' },
                  { k: 'rows checked', v: String(state.chain.checked) },
                ]}
              />
            )}
            {state.decisionLog && state.decisionLog.length > 0 && (
              <div className="chain">
                {state.decisionLog.map((r) => (
                  <div className="chain__row" key={r.seq}>
                    <div className="chain__seq">#{r.seq}</div>
                    <div>
                      <div>
                        {r.action} <span className="muted">/ {r.lawful_basis}</span>
                      </div>
                      <div className="chain__hash">
                        {short(r.prev_hash, 12)} <span className="chain__link">-&gt;</span> {short(r.hash, 12)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {state.rbac && (
              <>
                <CodeBlock>{state.rbac.attempted}</CodeBlock>
                <KeyValue
                  items={[
                    { k: 'as agent role', v: state.rbac.denied ? 'DENIED' : 'not restricted (local root)', tone: state.rbac.denied ? 'ok' : undefined },
                    { k: 'sqlstate', v: state.rbac.sqlstate || '(none)' },
                    { k: 'message', v: state.rbac.message },
                  ]}
                />
              </>
            )}
            <div className="note">
              GDPR Article 17 erases the personal data; EU AI Act Article 19 keeps the decision log.
              Both hold, from one transaction.
            </div>
          </>
        )
    }
  }

  return (
    <div className="layout">
      <nav className="rail">
        <div className="rail__title">Erasure loop</div>
        {STAGES.map((meta) => {
          const style: StyleWithVars = { '--hue': meta.hue }
          return (
            <button
              key={meta.id}
              className="rail__item"
              style={style}
              onClick={() => scrollToStage(meta.id)}
            >
              <span className="rail__num">{meta.n}</span>
              <span className="rail__label">{meta.title}</span>
              <StatusDot status={state.status[meta.id]} />
            </button>
          )
        })}
        <div style={{ display: 'flex', gap: '8px', marginTop: '10px', padding: '0 4px' }}>
          <button className="btn btn--accent" onClick={() => void actions.runAll()} disabled={busy}>
            {busy ? 'Running...' : 'Autopilot'}
          </button>
          <button className="btn btn--ghost" onClick={actions.reset} disabled={busy}>
            Reset
          </button>
        </div>
        {isMock && <div className="rail__title" style={{ paddingTop: '10px' }}>mock data (no backend)</div>}
      </nav>

      <div className="panel">
        {STAGES.map((meta) => (
          <div key={meta.id} style={{ marginBottom: '18px' }}>
            <Stage meta={meta} status={state.status[meta.id]}>
              {body(meta)}
            </Stage>
          </div>
        ))}
      </div>
    </div>
  )
}

const RECORDED_NODE_KILL = `# after: docker stop roach2  (quorum: 2/3 survive)
decision_log  : present   (seq 2, action=erasure)
subject_keys  : 0 rows    (key destroyed)
erasure_record: present   (proof_ref set)
# roach2 restarted -> catches up via Raft`
