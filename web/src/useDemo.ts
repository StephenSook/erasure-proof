import { useCallback, useMemo, useRef, useState } from 'react'
import {
  type ChainResult,
  type DecisionRow,
  type DemoApi,
  type EraseResponse,
  getClient,
  type InversionGoldenRun,
  type MemoryView,
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
        const mem = await c.getMemory(ing.subject_id)
        return {
          subjectId: ing.subject_id,
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
    clientRef.current = injected ?? getClient()
    setState(initialState())
  }, [injected])

  const actions = useMemo(
    () => ({ runMemory, runLeak, runEnvelope, runErase, runDurability, runAudit, runAll, reset }),
    [runMemory, runLeak, runEnvelope, runErase, runDurability, runAudit, runAll, reset],
  )

  return { state, actions }
}
