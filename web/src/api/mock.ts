// A stateful in-memory DemoApi used for standalone dev, CI, Playwright, and component tests. It
// mirrors the intended CLOUD behaviour (e.g. the RBAC write is denied with SQLSTATE 42501), so the
// console runs end to end without a backend. createMockClient() returns a fresh instance per caller
// so tests never share state.

import {
  ApiError,
  type ChainResult,
  type DecisionRow,
  type DemoApi,
  type EraseResponse,
  type InversionConfig,
  type InversionGoldenRun,
  type LiveInversion,
  type MemoryView,
  type ProofView,
  type RbacResult,
} from './types'

const DEMO_SENTENCE = 'Stephen Sookra is a full-stack developer who builds on CockroachDB and AWS.'
const FIXED_TIME = '2026-07-10T12:00:00Z'
const FINGERPRINT = '1340345376cafe1381f214c4f7102e7aec5c6a18e3514b9b11e07121f2e52691'

function goldenRun(): InversionGoldenRun {
  return {
    source: 'recorded',
    disclosure:
      'Recorded Vec2Text golden run (Modal T4). The live InvalidTag decrypt failure is the actual proof.',
    sentence: DEMO_SENTENCE,
    recovered_text: DEMO_SENTENCE + ' ',
    post_erasure_text: 's'.repeat(60) + '.',
    model: 'sentence-transformers/gtr-t5-base (768-dim), vec2text 0.0.13, transformers 4.44.2',
    gpu: 'Modal T4 (serverless)',
    recorded_at: '2026-07-09',
    leak_num_steps: 50,
    leak_sequence_beam_width: 8,
    consent: "The sentence is the author's own public bio line (self-consented data).",
  }
}

// Mock proofs are REALLY signed at runtime with a throwaway WebCrypto P-256 key, so the /proof
// verifier page is fully demonstrable against the mock (labeled mock; the key lives only in this
// tab). WebCrypto emits raw r||s signatures; the verifier accepts both raw and DER.
async function signMockProof(body: string): Promise<{ signature: string; pem: string }> {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      kp.privateKey,
      new TextEncoder().encode(body),
    ),
  )
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))
  let bin = ''
  for (const b of sig) {
    bin += String.fromCharCode(b)
  }
  const sigB64 = btoa(bin)
  let spkiBin = ''
  for (const b of spki) {
    spkiBin += String.fromCharCode(b)
  }
  const lines = btoa(spkiBin).match(/.{1,64}/g) ?? []
  const pem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`
  return { signature: sigB64, pem }
}

export function createMockClient(): DemoApi {
  let subjectId = ''
  let erased = false
  let proofBody = ''
  let proofSignature = ''
  let signerPem = ''

  const requireSubject = () => {
    if (!subjectId) {
      throw new ApiError(404, 'no memory for subject')
    }
  }

  // The methods are async so a thrown ApiError surfaces as a rejected promise, matching the real
  // HTTP client's contract (an error is a rejection, never a synchronous throw).
  return {
    async ingest() {
      subjectId = '11111111-2222-4333-8444-555555555555'
      erased = false
      return { subject_id: subjectId, memory_id: 'aaaaaaaa-0000-4000-8000-000000000001' }
    },
    async getMemory() {
      requireSubject()
      const view: MemoryView = {
        subject_id: subjectId,
        memory_id: 'aaaaaaaa-0000-4000-8000-000000000001',
        content_len: 74,
        embedding_present: !erased,
        embedding_len: 3088,
        key_fingerprint: erased ? '' : FINGERPRINT,
        created_at: FIXED_TIME,
      }
      return view
    },
    async getInversion() {
      return goldenRun()
    },
    async getInversionConfig(): Promise<InversionConfig> {
      // The mock has no GPU worker; advertise live as unavailable so the UI shows the recorded
      // path. A real deploy with MODAL_INVERT_* set flips this to true.
      return { live_available: false }
    },
    async liveInversion(embeddingB64: string): Promise<LiveInversion> {
      // No GPU in the mock: mirror cryptod's honest fallback shape so the UI code path is exercised.
      const digest = await crypto.subtle.digest(
        'SHA-256',
        Uint8Array.from(atob(embeddingB64), (c) => c.charCodeAt(0)),
      )
      const inputSha = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join(
        '',
      )
      return {
        source: 'recorded_golden_run',
        recovered_text: DEMO_SENTENCE + ' ',
        disclosure: goldenRun().disclosure as string,
        input_sha256: inputSha,
        fell_back: true,
        fallback_reason: 'mock has no GPU worker',
      }
    },
    async erase() {
      requireSubject()
      if (erased) {
        throw new ApiError(409, 'already erased')
      }
      erased = true
      // subject_hash must be the REAL SHA-256 of the subject id: the verifier page checks the
      // signed binding client-side, in mock mode too.
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(subjectId))
      const subjectHash = Array.from(new Uint8Array(digest), (b) =>
        b.toString(16).padStart(2, '0'),
      ).join('')
      proofBody = JSON.stringify({
        source: 'MOCK (runtime-signed with a throwaway key in this tab)',
        subject_hash: subjectHash,
        decision_log_seq: 2,
        chain_head: '22'.repeat(32),
        key_state: 'wrapped_key_destroyed',
        occurred_at: FIXED_TIME,
      })
      const signed = await signMockProof(proofBody)
      proofSignature = signed.signature
      signerPem = signed.pem
      // These byte fields are not decoded or displayed by the console; low-entropy placeholders keep
      // the mock free of anything a secret scanner would flag as a high-entropy key.
      const resp: EraseResponse = {
        result: {
          decision_log_seq: 2,
          subject_hash: 'mock-subject-hash',
          wrapped_key_fingerprint: 'mock-fingerprint',
          decision_log_head: 'mock-chain-head',
          kms_key_arn: 'arn:aws:kms:us-east-1:000000000000:key/demo',
          key_origin: 'GENERATE_DATA_KEY',
        },
        proof_ref: 's3://erasure-proof-anchors/subject/2.json',
      }
      return resp
    },
    async getProof() {
      if (!erased) {
        throw new ApiError(404, 'no erasure record for subject')
      }
      const proof: ProofView = {
        subject_id: subjectId,
        requested_at: FIXED_TIME,
        committed_at: FIXED_TIME,
        decision_log_seq: 2,
        fingerprint: FINGERPRINT,
        kms_key_arn: 'arn:aws:kms:us-east-1:000000000000:key/demo',
        proof_ref: 's3://erasure-proof-anchors/subject/2.json',
        proof_body: proofBody,
        proof_signature: proofSignature,
        signer_pubkey_pem: signerPem,
      }
      return proof
    },
    async getDecisionLog() {
      const rows: DecisionRow[] = [
        {
          seq: 1,
          subject_hash: FINGERPRINT,
          action: 'ingest',
          lawful_basis: 'gdpr_art_17',
          occurred_at: FIXED_TIME,
          prev_hash: '00'.repeat(32),
          hash: '11'.repeat(32),
        },
      ]
      if (erased) {
        rows.push({
          seq: 2,
          subject_hash: FINGERPRINT,
          action: 'erasure',
          lawful_basis: 'gdpr_art_17',
          occurred_at: FIXED_TIME,
          prev_hash: '11'.repeat(32),
          hash: '22'.repeat(32),
        })
      }
      return rows
    },
    async verifyChain() {
      const result: ChainResult = { intact: true, checked: erased ? 2 : 1, break_at_seq: null }
      return result
    },
    async rbacDemo() {
      const result: RbacResult = {
        attempted: "UPDATE decision_log SET action = 'tamper' WHERE seq = (SELECT max(seq) FROM decision_log)",
        denied: true,
        sqlstate: '42501',
        message: 'user agent_worker does not have UPDATE privilege on relation decision_log',
      }
      return result
    },
  }
}
