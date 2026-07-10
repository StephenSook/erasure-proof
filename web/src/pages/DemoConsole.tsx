import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '../components/Badge'
import { CodeBlock } from '../components/CodeBlock'
import { KeyValue } from '../components/KeyValue'
import { LcdCounter } from '../components/LcdCounter'
import { Stage } from '../components/Stage'
import { StatusDot } from '../components/StatusDot'
import { demoMemory } from '../data/demoMemory'
import { STAGES, type StageId, type StageMeta } from '../demoStages'
import { pulseStageBar, revealResults, revealStages, scrambleIn } from '../fx'
import { motionEnabled } from '../motion'
import { useDemo } from '../useDemo'

type StyleWithVars = CSSProperties & Record<`--${string}`, string>

const short = (s: string | null | undefined, n = 20): string =>
  !s ? '' : s.length > n ? `${s.slice(0, n)}...` : s

const isMock = import.meta.env.VITE_USE_MOCK === '1'

function scrollToStage(id: StageId) {
  // An explicit 'smooth' request overrides the OS reduced-motion setting, so gate it too.
  document.getElementById(`stage-${id}`)?.scrollIntoView({
    behavior: motionEnabled() ? 'smooth' : 'auto',
    block: 'start',
  })
}

export function DemoConsole() {
  const { state, actions } = useDemo()
  const [writerTurn, setWriterTurn] = useState('')

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

  // Motion (presentation only; every effect is a no-op under reduced motion / ?minimal=1 / tests).
  const panelRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (panelRef.current) {
      revealStages(panelRef.current)
    }
  }, [])

  // Probe once whether the live GPU worker and the live Bedrock agent are wired, so each live
  // control reflects reality (a deploy without MODAL_INVERT_* / AGENTS_LIVE shows the recorded path).
  useEffect(() => {
    void actions.checkLive()
    void actions.checkAgent()
  }, [actions])

  // On each stage completing, flare its bar, stagger its results in, and scramble-in any value
  // marked data-scramble (the leak's recovered text, the erase after-state). Completion is detected
  // via the monotonic doneSeq counter, not status diffing, because React can batch the running and
  // done status updates into one commit and hide the transition. Results render in the same commit
  // that bumps doneSeq, so the elements exist by the time this effect runs.
  const prevSeq = useRef(state.doneSeq)
  useEffect(() => {
    const prev = prevSeq.current
    prevSeq.current = state.doneSeq
    for (const id of Object.keys(state.doneSeq) as StageId[]) {
      if (state.doneSeq[id] > prev[id]) {
        const el = document.getElementById(`stage-${id}`)
        if (el) {
          pulseStageBar(el)
          revealResults(el)
          el.querySelectorAll<HTMLElement>('[data-scramble]').forEach((n) => scrambleIn(n))
        }
      }
    }
  }, [state.doneSeq])

  // The LCD instrument strip readouts.
  const latestMemory = state.memoryAfter ?? state.memory
  const lcdEmbed = state.memory ? String(state.memory.embedding_len) : '----'
  const lcdKey = latestMemory ? (latestMemory.key_fingerprint ? 'ON' : 'OFF') : '--'
  const lcdSeq = state.erase ? String(state.erase.result.decision_log_seq) : '--'
  const lcdChain = state.chain ? (state.chain.intact ? 'OK' : 'ERR') : '--'

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

  function memoryWriterPanel() {
    const written = state.memWriter
    return (
      <div className="live-leak">
        <div className="live-leak__head">
          <Badge kind={state.memWriterAvailable ? 'live' : 'recorded'}>
            {state.memWriterAvailable ? 'Live AI memory-writer' : 'Recorded memory-writer'}
          </Badge>
        </div>
        <div className="note">
          Or let the agent write the memory: type something a person told an assistant. Claude
          distils the one durable fact, embeds it, and stores it as the memory this loop then erases.
        </div>
        <textarea
          className="writer-input"
          rows={2}
          placeholder="e.g. Hi, I'm Marie Curie and I discovered radium and polonium in 1898."
          value={writerTurn}
          onChange={(e) => setWriterTurn(e.target.value)}
        />
        <div className="live-leak__head">
          <button
            className="btn btn--small"
            onClick={() => void actions.runMemoryWriter(writerTurn)}
            disabled={state.memWriterStatus === 'running' || writerTurn.trim().length === 0}
          >
            {state.memWriterStatus === 'running' ? 'The agent is writing the memory...' : 'Write it with the agent'}
          </button>
        </div>
        {state.memWriterError && <div className="note note--error">{state.memWriterError}</div>}
        {written && state.memWriterStatus === 'done' && (
          <>
            <KeyValue
              items={[
                { k: 'distilled memory', v: written.memory_text, tone: 'ok' },
                { k: 'source', v: written.source === 'live_bedrock' ? 'live Claude on Bedrock' : 'recorded (agent not wired)', tone: written.source === 'live_bedrock' ? 'ok' : undefined },
                { k: 'stored as subject', v: short(written.subject_id, 20) },
              ]}
            />
            <div className="note">
              This memory is now the subject the rest of the loop erases.
              {state.memWriterAvailable
                ? ' It is a real GTR embedding, so the live inversion beat reconstructs your own words.'
                : ' (Recorded writer: on a wired deploy the live inversion beat would reconstruct your own words from its embedding.)'}
            </div>
          </>
        )}
      </div>
    )
  }

  function liveLeakPanel() {
    // Only offer the live GPU run where a worker is actually wired; otherwise the recorded run
    // above stands on its own (honest: no dead button).
    if (!state.liveAvailable) {
      return (
        <div className="note">
          Live GPU inversion is not wired on this deployment. The recorded run above is the
          reproducible attack; its provenance is on the Trust page.
        </div>
      )
    }
    const live = state.liveInversion
    // Compare against the CURRENT subject's hash (the demo memory, or the judge's agent-written
    // one), so the match-check is honest whichever memory is loaded.
    const matches = live?.input_sha256 === state.currentEmbeddingSha256
    return (
      <div className="live-leak">
        <div className="live-leak__head">
          <Badge kind="live">Live GPU</Badge>
          <button
            className="btn btn--small"
            onClick={() => void actions.runLiveLeak()}
            disabled={state.liveStatus === 'running'}
          >
            {state.liveStatus === 'running'
              ? 'Inverting on a Modal T4 GPU...'
              : 'Run the attack yourself on a GPU (~60-90s)'}
          </button>
        </div>
        {state.liveStatus === 'running' && (
          <div className="note">
            A real T4 GPU is reconstructing the sentence from the embedding bytes, live. This is the
            honest cost of doing it for real: cold start plus the inversion.
          </div>
        )}
        {state.liveError && <div className="note note--error">{state.liveError}</div>}
        {live && state.liveStatus === 'done' && (
          <>
            <KeyValue
              items={[
                { k: 'recovered text (live)', v: String(live.recovered_text ?? ''), tone: 'bad', scramble: true },
                { k: 'source', v: live.source === 'live_gpu' ? 'live GPU (Modal T4)' : 'recorded (worker fell back)', tone: live.source === 'live_gpu' ? 'ok' : undefined },
                ...(live.seconds ? [{ k: 'seconds', v: String(live.seconds) }] : []),
                ...(live.device ? [{ k: 'device', v: String(live.device) }] : []),
                { k: 'inverted vector sha-256', v: short(live.input_sha256, 24) },
                { k: 'matches the vector shown', v: matches ? 'yes, same sha-256' : 'NO', tone: matches ? 'ok' : 'bad' },
              ]}
            />
            <div className="note">
              {String(live.disclosure ?? '')}{' '}
              {live.fell_back
                ? 'The GPU worker was unreachable, so this fell back to the recorded run, labeled honestly.'
                : 'You just ran the reconstruction yourself, on the exact vector the console shows.'}
            </div>
          </>
        )}
      </div>
    )
  }

  function stageResult(id: StageId) {
    switch (id) {
      case 'memory':
        return (
          <>
            <div className="note">
              Storing: <span className="mono">{state.memWriter?.memory_text ?? demoMemory.text}</span>
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
            {memoryWriterPanel()}
          </>
        )
      case 'leak':
        return (
          state.inversion && (
            <>
              <KeyValue
                items={[
                  { k: 'recovered text', v: String(state.inversion.recovered_text ?? ''), tone: 'bad', scramble: true },
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
              {state.memWriter && (
                <div className="note">
                  The recorded run above is for the demo sentence. Your agent-written memory is a
                  different vector; use the live GPU button below to invert it.
                </div>
              )}
              {liveLeakPanel()}
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
                  { k: 'live vector', v: state.memoryAfter.embedding_present ? 'STILL PRESENT' : 'purged to NULL', tone: state.memoryAfter.embedding_present ? 'bad' : 'ok', scramble: true },
                  { k: 'subject key', v: state.memoryAfter.key_fingerprint ? 'STILL PRESENT' : 'destroyed (row gone)', tone: state.memoryAfter.key_fingerprint ? 'bad' : 'ok', scramble: true },
                ]}
              />
            )}
            {state.proof && (
              <div className="note">
                Proof record read back:{' '}
                <span className="mono">{state.proof.proof_ref ?? '(anchoring pending)'}</span>
                {state.proof.committed_at ? `, committed ${state.proof.committed_at}` : ''}{' '}
                <Link to={`/proof/${state.proof.subject_id}`}>Verify this proof in your browser -&gt;</Link>
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
            {liveTimeline()}
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
            {forensicsAgentPanel()}
          </>
        )
    }
  }

  function liveTimeline() {
    const rows = state.streamRows
    const badge =
      state.streamStatus === 'live'
        ? { kind: 'live' as const, text: 'Live (CockroachDB changefeed)' }
        : state.streamStatus === 'snapshot'
          ? { kind: 'recorded' as const, text: 'Snapshot (changefeed not wired)' }
          : state.streamStatus === 'error'
            ? { kind: 'recorded' as const, text: 'Stream reconnecting' }
            : { kind: 'recorded' as const, text: 'Connecting...' }
    return (
      <div className="live-leak">
        <div className="live-leak__head">
          <Badge kind={badge.kind}>{badge.text}</Badge>
          <span className="muted">decision log, streamed as it grows</span>
        </div>
        {rows.length > 0 ? (
          <div className="chain">
            {rows.map((r) => (
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
        ) : (
          <div className="note">No decision-log rows yet. Run the loop and watch them append here.</div>
        )}
      </div>
    )
  }

  function forensicsAgentPanel() {
    const audit = state.agentAudit
    // Tone on the SERVER'S read of the evidence, never the model's free text. If the model's wording
    // and the evidence disagree, the evidence is authoritative and we say so.
    const provenByEvidence = audit?.evidence_proven === true
    const provenByText = audit?.verdict?.startsWith('VERDICT: PROVEN') ?? false
    const disagree = audit != null && provenByText !== provenByEvidence
    return (
      <div className="live-leak">
        <div className="live-leak__head">
          <Badge kind={state.agentAvailable ? 'live' : 'recorded'}>
            {state.agentAvailable ? 'Live AI agent' : 'Recorded verdict'}
          </Badge>
          <button
            className="btn btn--small"
            onClick={() => void actions.runForensics()}
            disabled={state.agentStatus === 'running' || !state.subjectId}
          >
            {state.agentStatus === 'running'
              ? 'The agent is gathering evidence...'
              : 'Have the AI agent prove the erasure'}
          </button>
        </div>
        {state.agentStatus === 'running' && state.agentAvailable && (
          <div className="note">
            Claude is calling the read-only forensic tools, one at a time, to decide whether the
            erasure is provable. It can only cite what the tools return.
          </div>
        )}
        {state.agentError && <div className="note note--error">{state.agentError}</div>}
        {audit && state.agentStatus === 'done' && (
          <>
            <KeyValue
              items={[
                { k: 'verdict', v: String(audit.verdict ?? ''), tone: provenByEvidence ? 'ok' : 'bad' },
                { k: 'evidence proves erasure', v: provenByEvidence ? 'yes' : 'no', tone: provenByEvidence ? 'ok' : 'bad' },
                { k: 'source', v: audit.source === 'live_bedrock' ? 'live Claude on Bedrock' : 'recorded (agent not wired)', tone: audit.source === 'live_bedrock' ? 'ok' : undefined },
                { k: 'rounds', v: String(audit.rounds ?? '') },
              ]}
            />
            {disagree && (
              <div className="note note--error">
                The agent&apos;s wording and the tool evidence disagree. The evidence is
                authoritative: this erasure is {provenByEvidence ? 'proven' : 'NOT proven'} by what
                the read-only tools returned.
              </div>
            )}
            {audit.tool_calls && audit.tool_calls.length > 0 && (
              <div className="agent-trace">
                {audit.tool_calls.map((c, i) => (
                  <div className="agent-trace__row" key={`${c.name}-${i}`}>
                    <div className="agent-trace__tool">
                      {c.name}({JSON.stringify(c.input)})
                    </div>
                    <CodeBlock>{JSON.stringify(c.output)}</CodeBlock>
                  </div>
                ))}
              </div>
            )}
            <div className="note">
              {String(audit.disclosure ?? '')} The verdict is toned by our own check of the trace,
              not the model&apos;s wording; the trace above is the agent&apos;s actual evidence.
            </div>
          </>
        )}
      </div>
    )
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

      <div className="panel" ref={panelRef}>
        <div className="lcd-strip">
          <LcdCounter label="embed bytes" value={lcdEmbed} width={4} />
          <LcdCounter label="subject key" value={lcdKey} family="14" width={3} />
          <LcdCounter label="erase seq" value={lcdSeq} width={3} />
          <LcdCounter label="chain" value={lcdChain} family="14" width={3} />
        </div>
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
