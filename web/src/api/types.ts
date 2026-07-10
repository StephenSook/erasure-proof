// Response shapes returned by the Go api and the /api demo gateway. Field names match the JSON tags
// on the server exactly (e.g. decision_log_seq, wrapped_key_fingerprint).

export interface IngestResult {
  subject_id: string
  memory_id: string
}

export interface MemoryView {
  subject_id: string
  memory_id: string
  content_len: number
  embedding_present: boolean
  embedding_len: number
  key_fingerprint: string // hex; empty once the key row is erased
  created_at: string
}

export interface EraseResult {
  decision_log_seq: number
  subject_hash: string // base64
  wrapped_key_fingerprint: string // base64
  decision_log_head: string // base64
  kms_key_arn: string
  key_origin: string
}

export interface EraseResponse {
  result: EraseResult
  proof_ref?: string
  proof_pending?: boolean
}

export interface ProofView {
  subject_id: string
  requested_at: string
  committed_at: string | null
  decision_log_seq: number | null
  fingerprint: string | null
  kms_key_arn: string | null
  proof_ref: string | null
  // The signed proof document: proof_body is the EXACT canonical bytes the ECDSA signature covers
  // (verified verbatim in the browser); the signer key is served alongside for cross-checking.
  proof_body: string | null
  proof_signature: string | null
  signer_pubkey_pem: string | null
}

export interface DecisionRow {
  seq: number
  subject_hash: string
  action: string
  lawful_basis: string
  occurred_at: string
  prev_hash: string
  hash: string
}

export interface ChainResult {
  intact: boolean
  checked: number
  break_at_seq: number | null
}

export interface RbacResult {
  attempted: string
  denied: boolean
  sqlstate: string
  message: string
}

export interface InversionGoldenRun {
  sentence?: string
  recovered_text?: string
  post_erasure_text?: string
  model?: string
  gpu?: string
  recorded_at?: string
  consent?: string
  note?: string
  disclosure?: string
  [key: string]: unknown
}

// InversionConfig tells the UI whether the live GPU worker is wired, so the live button appears
// only when it can actually run.
export interface InversionConfig {
  live_available: boolean
}

// LiveInversion is the result of a live GPU inversion. source is "live_gpu" when the GPU ran, or
// "recorded_golden_run" when cryptod fell back; input_sha256 (live path) is the SHA-256 of the
// exact embedding bytes inverted, so the UI can prove the run matches the vector shown.
export interface LiveInversion {
  source: string
  recovered_text?: string
  seconds?: number
  device?: string
  input_sha256?: string
  disclosure?: string
  fell_back?: boolean
  fallback_reason?: string
  [key: string]: unknown
}

// ApiError carries the HTTP status so callers can distinguish 404 (not found yet) from real faults.
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// AgentConfig tells the UI which live Bedrock agent features are wired.
export interface AgentConfig {
  live_available: boolean
  forensics_available?: boolean
  memory_writer_available?: boolean
}

// MemoryWriterResult is the agent-written memory: the distilled fact and where it was stored.
// source is "live_bedrock" when the real agent ran, "recorded" for the honest mock.
export interface MemoryWriterResult {
  source: string
  memory_text: string
  subject_id: string
  memory_id: string
}

// AgentToolCall is one recorded tool invocation in the agent's evidence trace.
export interface AgentToolCall {
  name: string
  input: Record<string, unknown>
  output: Record<string, unknown>
}

// ForensicsAudit is the agent's verdict plus its full tool-call trace. source is "live_bedrock"
// when the real agent ran, or "recorded" for the honest mock fallback.
export interface ForensicsAudit {
  verdict: string
  tool_calls: AgentToolCall[] | null
  rounds: number
  source?: string
  disclosure?: string
  // The server's own read of the tool trace (NOT the model's text), so the UI tones the verdict on
  // evidence and flags any case where the model's wording disagrees with what the tools returned.
  evidence_proven: boolean
}

export interface DemoApi {
  ingest(contentB64: string, embeddingB64: string): Promise<IngestResult>
  getMemory(subjectId: string): Promise<MemoryView>
  getInversion(): Promise<InversionGoldenRun>
  getInversionConfig(): Promise<InversionConfig>
  liveInversion(embeddingB64: string): Promise<LiveInversion>
  getAgentConfig(): Promise<AgentConfig>
  forensicsAudit(subjectId: string): Promise<ForensicsAudit>
  writeMemory(turn: string): Promise<MemoryWriterResult>
  erase(subjectId: string, lawfulBasis?: string): Promise<EraseResponse>
  getProof(subjectId: string): Promise<ProofView>
  getDecisionLog(): Promise<DecisionRow[]>
  verifyChain(): Promise<ChainResult>
  rbacDemo(): Promise<RbacResult>
}
