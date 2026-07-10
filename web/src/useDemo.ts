import { useCallback, useMemo, useRef, useState } from 'react'
import {
  type ChainResult,
  type DecisionRow,
  type DemoApi,
  type EraseResponse,
  type ForensicsAudit,
  getClient,
  type InversionGoldenRun,
  type LiveInversion,
  type MemoryView,
  type MemoryWriterResult,
  type ProofView,
  type RbacResult,
} from './api'
import { demoMemory } from './data/demoMemory'
import { STAGES, type StageId, type StageStatus } from './demoStages'

export interface DemoState {
  subjectId: string
  memory?: MemoryView // after stage 1 (and refreshed by stage 3)
  memoryAfter?: MemoryView // after erasure (embedding + key gone)
  inversion?: InversionGoldenRun
  // Live GPU inversion of the CURRENT subject's embedding: the "run the attack yourself" beat.
  // These track whichever memory is loaded (the demo memory, or an agent-written one).
  currentEmbeddingB64: string
  currentEmbeddingSha256: string
  liveInversion?: LiveInversion
  liveStatus: 'idle' | 'running' | 'done' | 'error'
  liveError?: string
  liveAvailable?: boolean
  // Live Bedrock forensics agent: the AI proves the erasure on screen.
  agentAudit?: ForensicsAudit
  agentStatus: 'idle' | 'running' | 'done' | 'error'
  agentError?: string
  agentAvailable?: boolean
  // Live Bedrock memory-writer: the AI distils + stores a memory the loop then erases.
  memWriter?: MemoryWriterResult
  memWriterStatus: 'idle' | 'running' | 'done' | 'error'
  memWriterError?: string
  memWriterAvailable?: boolean
  erase?: EraseResponse
  proof?: ProofView
  decisionLog?: DecisionRow[]
  chain?: ChainResult
  rbac?: RbacResult
  status: Record<StageId, StageStatus>
  error: Partial<Record<StageId, string>>
  // Monotonic per-stage completion counter. React can batch the 'running' and 'done' status updates
  // into one commit (fast mocks resolve in microtasks), so completion effects diff this counter, not
  // the committed status snapshots, to never miss a run.
  doneSeq: Record<StageId, number>
}

const idleStatus = (): Record<StageId, StageStatus> =>
  Object.fromEntries(STAGES.map((s) => [s.id, 'idle'])) as Record<StageId, StageStatus>

const zeroSeq = (): Record<StageId, number> =>
  Object.fromEntries(STAGES.map((s) => [s.id, 0])) as Record<StageId, number>

const initialState = (): DemoState => ({
  subjectId: '',
  currentEmbeddingB64: demoMemory.embeddingB64,
  currentEmbeddingSha256: demoMemory.embeddingSha256,
  liveStatus: 'idle',
  agentStatus: 'idle',
  memWriterStatus: 'idle',
  status: idleStatus(),
  error: {},
  doneSeq: zeroSeq(),
})

export function useDemo(injected?: DemoApi) {
  // Lazy init: getClient() runs once, not on every render (React keeps only the first useRef value,
  // but the argument would still be evaluated each render).
  const clientRef = useRef<DemoApi | null>(null)
  clientRef.current ??= injected ?? getClient()
  const subjectRef = useRef('')
  // The current subject's embedding, mirrored in a ref so runLiveLeak (a stable callback) always
  // inverts the loaded memory, not a stale-closure value.
  const embeddingRef = useRef<string>(demoMemory.embeddingB64)
  const [state, setState] = useState<DemoState>(initialState)

  const setStatus = useCallback((id: StageId, st: StageStatus, err?: string) => {
    setState((s) => ({ ...s, status: { ...s.status, [id]: st }, error: { ...s.error, [id]: err } }))
  }, [])

  const step = useCallback(
    async (id: StageId, fn: (client: DemoApi) => Promise<Partial<DemoState>>) => {
      setStatus(id, 'running')
      try {
        const p = await fn(clientRef.current!)
        setState((s) => ({
          ...s,
          ...p,
          status: { ...s.status, [id]: 'done' },
          error: { ...s.error, [id]: undefined },
          doneSeq: { ...s.doneSeq, [id]: s.doneSeq[id] + 1 },
        }))
      } catch (e) {
        setStatus(id, 'error', e instanceof Error ? e.message : String(e))
        throw e
      }
    },
    [setStatus],
  )

  const requireSubject = useCallback(() => {
    if (!subjectRef.current) {
      throw new Error('Run stage 1 (store a memory) first.')
    }
    return subjectRef.current
  }, [])

  const runMemory = useCallback(
    () =>
      step('memory', async (c) => {
        const ing = await c.ingest(demoMemory.contentB64, demoMemory.embeddingB64)
        subjectRef.current = ing.subject_id
        embeddingRef.current = demoMemory.embeddingB64
        const mem = await c.getMemory(ing.subject_id)
        return {
          subjectId: ing.subject_id,
          currentEmbeddingB64: demoMemory.embeddingB64,
          currentEmbeddingSha256: demoMemory.embeddingSha256,
          memWriter: undefined,
          memWriterStatus: 'idle' as const,
          memory: mem,
          memoryAfter: undefined,
          erase: undefined,
          proof: undefined,
        }
      }),
    [step],
  )

  const runLeak = useCallback(
    () => step('leak', async (c) => ({ inversion: await c.getInversion() })),
    [step],
  )

  // Probe whether a live GPU worker is wired so the UI shows the live button only when it can run.
  const checkLive = useCallback(async () => {
    try {
      const cfg = await clientRef.current!.getInversionConfig()
      setState((s) => ({ ...s, liveAvailable: cfg.live_available }))
    } catch {
      setState((s) => ({ ...s, liveAvailable: false }))
    }
  }, [])

  // Run the attack live on a real GPU, on the exact demo embedding shown. cryptod falls back to the
  // recorded run if the worker is down, so the returned source label always states which path ran.
  const runLiveLeak = useCallback(async () => {
    // Invert the CURRENT subject's vector (the demo memory, or the judge's agent-written one), so
    // the live beat reconstructs the actual memory on screen, never a hardcoded one.
    setState((s) => ({ ...s, liveStatus: 'running', liveError: undefined }))
    try {
      const live = await clientRef.current!.liveInversion(embeddingRef.current)
      setState((s) => ({ ...s, liveInversion: live, liveStatus: 'done' }))
    } catch (e) {
      setState((s) => ({
        ...s,
        liveStatus: 'error',
        liveError: e instanceof Error ? e.message : String(e),
      }))
    }
  }, [])

  // Probe which live Bedrock agent features are wired.
  const checkAgent = useCallback(async () => {
    try {
      const cfg = await clientRef.current!.getAgentConfig()
      setState((s) => ({
        ...s,
        agentAvailable: cfg.forensics_available ?? cfg.live_available,
        memWriterAvailable: cfg.memory_writer_available ?? false,
      }))
    } catch {
      setState((s) => ({ ...s, agentAvailable: false, memWriterAvailable: false }))
    }
  }, [])

  // Have the agent write a memory from a typed sentence: Claude distils the durable fact, it is
  // embedded and stored, and it BECOMES the subject the rest of the loop erases (so the leak and
  // erase beats run on the judge's own agent-written memory). Mock mode stores a labeled recorded
  // memory the same way.
  const runMemoryWriter = useCallback(
    async (turn: string) => {
      setState((s) => ({ ...s, memWriterStatus: 'running', memWriterError: undefined }))
      try {
        const written = await clientRef.current!.writeMemory(turn)
        subjectRef.current = written.subject_id
        embeddingRef.current = written.embedding_b64
        const mem = await clientRef.current!.getMemory(written.subject_id)
        setState((s) => ({
          ...s,
          memWriter: written,
          memWriterStatus: 'done',
          subjectId: written.subject_id,
          currentEmbeddingB64: written.embedding_b64,
          currentEmbeddingSha256: written.embedding_sha256,
          memory: mem,
          memoryAfter: undefined,
          erase: undefined,
          proof: undefined,
          inversion: undefined,
          liveInversion: undefined,
          liveStatus: 'idle',
          // Mark stage 1 complete so the loop can continue on the agent-written memory, and clear a
          // prior stage-1 error so its banner does not linger over this success.
          status: { ...s.status, memory: 'done' },
          error: { ...s.error, memory: undefined },
          doneSeq: { ...s.doneSeq, memory: s.doneSeq.memory + 1 },
        }))
      } catch (e) {
        setState((s) => ({
          ...s,
          memWriterStatus: 'error',
          memWriterError: e instanceof Error ? e.message : String(e),
        }))
      }
    },
    [],
  )

  // Have the AI agent prove the erasure: a Claude tool-use loop over the read-only tools, returning
  // a verdict with its evidence trace. Mock mode returns an honestly-labeled recorded verdict.
  const runForensics = useCallback(async () => {
    const id = subjectRef.current
    if (!id) {
      setState((s) => ({ ...s, agentStatus: 'error', agentError: 'Run stage 1 (store a memory) first.' }))
      return
    }
    setState((s) => ({ ...s, agentStatus: 'running', agentError: undefined }))
    try {
      const audit = await clientRef.current!.forensicsAudit(id)
      setState((s) => ({ ...s, agentAudit: audit, agentStatus: 'done' }))
    } catch (e) {
      setState((s) => ({
        ...s,
        agentStatus: 'error',
        agentError: e instanceof Error ? e.message : String(e),
      }))
    }
  }, [])

  const runEnvelope = useCallback(
    () => step('envelope', async (c) => ({ memory: await c.getMemory(requireSubject()) })),
    [step, requireSubject],
  )

  const runErase = useCallback(
    () =>
      step('erase', async (c) => {
        const id = requireSubject()
        const er = await c.erase(id)
        const after = await c.getMemory(id)
        const proof = await c.getProof(id)
        return { erase: er, memoryAfter: after, proof }
      }),
    [step, requireSubject],
  )

  // Durability runs on the local 3-node cluster (recorded); there is nothing to fetch here.
  const runDurability = useCallback(() => step('durability', () => Promise.resolve({})), [step])

  const runAudit = useCallback(
    () =>
      step('audit', async (c) => {
        const [decisionLog, chain, rbac] = await Promise.all([
          c.getDecisionLog(),
          c.verifyChain(),
          c.rbacDemo(),
        ])
        return { decisionLog, chain, rbac }
      }),
    [step],
  )

  const runAll = useCallback(async () => {
    try {
      await runMemory()
      await runLeak()
      await runEnvelope()
      await runErase()
      await runDurability()
      await runAudit()
    } catch {
      // A failed step has already recorded its error; stop the autopilot sequence.
    }
  }, [runMemory, runLeak, runEnvelope, runErase, runDurability, runAudit])

  const reset = useCallback(() => {
    subjectRef.current = ''
    embeddingRef.current = demoMemory.embeddingB64
    clientRef.current = injected ?? getClient()
    setState(initialState())
  }, [injected])

  const actions = useMemo(
    () => ({
      runMemory,
      runLeak,
      checkLive,
      runLiveLeak,
      checkAgent,
      runForensics,
      runMemoryWriter,
      runEnvelope,
      runErase,
      runDurability,
      runAudit,
      runAll,
      reset,
    }),
    [
      runMemory,
      runLeak,
      checkLive,
      runLiveLeak,
      checkAgent,
      runForensics,
      runMemoryWriter,
      runEnvelope,
      runErase,
      runDurability,
      runAudit,
      runAll,
      reset,
    ],
  )

  return { state, actions }
}
