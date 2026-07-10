// The real HTTP client. Uses relative paths by default (same-origin behind CloudFront in production,
// proxied to the local Go api in dev). Override the base with VITE_API_BASE if the api is elsewhere.

import {
  type AgentConfig,
  ApiError,
  type ChainResult,
  type ConsistencyView,
  type DecisionRow,
  type DemoApi,
  type EraseResponse,
  type ForensicsAudit,
  type InclusionView,
  type IngestResult,
  type InversionConfig,
  type InversionGoldenRun,
  type LiveInversion,
  type MemoryView,
  type MemoryWriterResult,
  type ProofView,
  type RbacResult,
  type TreeHead,
} from './types'

interface DecisionLogResponse {
  rows: DecisionRow[] | null
}

async function request<T>(base: string, method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: {} }
  if (body !== undefined) {
    ;(init.headers as Record<string, string>)['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  let resp: Response
  try {
    resp = await fetch(base + path, init)
  } catch (e) {
    throw new ApiError(0, `network error: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (!resp.ok) {
    let detail = ''
    try {
      const data = (await resp.json()) as { error?: string }
      detail = data.error ?? ''
    } catch {
      // non-JSON error body; the status is enough
    }
    throw new ApiError(resp.status, detail || `HTTP ${resp.status}`)
  }
  return (await resp.json()) as T
}

export function createHttpClient(base = ''): DemoApi {
  const b = base.replace(/\/$/, '')
  return {
    ingest(contentB64, embeddingB64) {
      return request<IngestResult>(b, 'POST', '/memories', {
        content: contentB64,
        embedding: embeddingB64,
      })
    },
    getMemory(subjectId) {
      return request<MemoryView>(b, 'GET', `/api/memory?subject_id=${encodeURIComponent(subjectId)}`)
    },
    getInversion() {
      return request<InversionGoldenRun>(b, 'GET', '/api/inversion')
    },
    getInversionConfig() {
      return request<InversionConfig>(b, 'GET', '/api/inversion/config')
    },
    liveInversion(embeddingB64) {
      return request<LiveInversion>(b, 'POST', '/api/inversion/live', { embedding: embeddingB64 })
    },
    getAgentConfig() {
      return request<AgentConfig>(b, 'GET', '/api/agent/config')
    },
    forensicsAudit(subjectId) {
      return request<ForensicsAudit>(b, 'POST', '/api/agent/forensics', { subject_id: subjectId })
    },
    writeMemory(turn) {
      return request<MemoryWriterResult>(b, 'POST', '/api/agent/memory-writer', { turn })
    },
    erase(subjectId, lawfulBasis = 'gdpr_art_17') {
      return request<EraseResponse>(b, 'POST', '/erase', {
        subject_id: subjectId,
        lawful_basis: lawfulBasis,
      })
    },
    getProof(subjectId) {
      return request<ProofView>(b, 'GET', `/api/proof?subject_id=${encodeURIComponent(subjectId)}`)
    },
    async getDecisionLog() {
      const data = await request<DecisionLogResponse>(b, 'GET', '/api/decision-log')
      return data.rows ?? []
    },
    verifyChain() {
      return request<ChainResult>(b, 'POST', '/api/verify-chain')
    },
    rbacDemo() {
      return request<RbacResult>(b, 'POST', '/api/rbac-demo')
    },
    getTreeHead() {
      return request<TreeHead>(b, 'GET', '/api/tree-head')
    },
    getInclusion(seq, treeSize) {
      const size = treeSize && treeSize > 0 ? `&size=${treeSize}` : ''
      return request<InclusionView>(b, 'GET', `/api/inclusion?seq=${seq}${size}`)
    },
    getConsistency(from, to) {
      const toParam = to && to > 0 ? `&to=${to}` : ''
      return request<ConsistencyView>(b, 'GET', `/api/consistency?from=${from}${toParam}`)
    },
    subscribeErasureStream(handlers) {
      // Server-Sent Events fed by the CockroachDB changefeed. EventSource auto-reconnects; onError
      // fires on a dropped connection so the UI can show a reconnecting state.
      const es = new EventSource(b + '/api/erasure-stream')
      es.addEventListener('snapshot', (e) => {
        const d = JSON.parse((e as MessageEvent).data) as { rows?: DecisionRow[]; live?: boolean }
        handlers.onSnapshot(d.rows ?? [], d.live ?? false)
      })
      es.addEventListener('row', (e) => {
        handlers.onRow(JSON.parse((e as MessageEvent).data) as DecisionRow)
      })
      es.onerror = () => handlers.onError?.('stream disconnected (reconnecting)')
      return () => es.close()
    },
  }
}
