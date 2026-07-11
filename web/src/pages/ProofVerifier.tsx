import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ApiError, type DemoApi, getClient, type ProofView } from '../api'
import { CodeBlock } from '../components/CodeBlock'
import { KeyValue, type KV } from '../components/KeyValue'
import {
  bytesToHex,
  hexToBytes,
  merkleLeafHash,
  pemToDer,
  sha256Hex,
  verifyConsistency,
  verifyInclusion,
  verifyProofSignature,
} from '../verify'

// What the page proves, precisely: the signed body is authentic under the served key AND names the
// subject in the URL (subject_hash == SHA-256(subject id), checked client-side). Facts rendered
// under the VERIFIED banner come from the SIGNED body; server-asserted extras are labeled as such.

type Status =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'notfound' }
  | { kind: 'pending'; proof: ProofView } // erased, proof not anchored yet (reconciler will)
  | { kind: 'error'; message: string }
  | { kind: 'malformed'; message: string } // undecodable proof data: corruption or tampering
  | { kind: 'failed' } // well-formed but the signature does not match
  | { kind: 'mismatch'; wantHash: string; gotHash: string } // valid signature, WRONG subject
  | {
      kind: 'verified'
      proof: ProofView
      body: Record<string, unknown>
      bodySha256: string
      keyFingerprint: string
      transparency: Transparency
    }

// The transparency check runs entirely in the browser against the SIGNED root and tree size: it
// recomputes the erasure's leaf from the signed decision_log_head (never trusting the server's
// leaf_hash), proves inclusion in the signed tree, and proves the current log is an append-only
// extension of that tree (a consistency proof). This closes the "signed root is a snapshot" gap.
type Transparency =
  | { state: 'unavailable' } // older proof with no Merkle fields
  | { state: 'checking' }
  | { state: 'error'; message: string }
  | {
      state: 'done'
      inclusionOk: boolean
      consistencyOk: boolean
      signedSize: number
      currentSize: number
      grew: boolean
    }

async function checkTransparency(body: Record<string, unknown>, api: DemoApi): Promise<Transparency> {
  const merkleRoot = String(body.merkle_root ?? '')
  const head = String(body.decision_log_head ?? '')
  const signedSize = Number(body.tree_size ?? 0)
  const seq = Number(body.decision_log_seq ?? 0)
  if (!merkleRoot || !head || signedSize <= 0 || seq <= 0) {
    return { state: 'unavailable' }
  }
  try {
    // Inclusion in the SIGNED tree, with the leaf recomputed from the signed head.
    const inc = await api.getInclusion(seq, signedSize)
    const leafHashHex = bytesToHex(await merkleLeafHash(hexToBytes(head)))
    const inclusionOk = await verifyInclusion(
      leafHashHex,
      inc.leaf_index,
      signedSize,
      inc.audit_path,
      merkleRoot,
    )
    // Consistency: the current log is an append-only extension of the signed tree. Verify in EVERY
    // case against the head the server actually presents, so the "append-only" verdict is never
    // inferred from a server-reported size alone.
    const head2 = await api.getTreeHead()
    const currentSize = head2.tree_size
    let consistencyOk: boolean
    const grew = currentSize > signedSize
    if (currentSize < signedSize) {
      // The server reports a SMALLER tree than the one it signed: truncation or rewrite, not
      // append-only. Fail closed.
      consistencyOk = false
    } else if (grew) {
      const cons = await api.getConsistency(signedSize, currentSize)
      consistencyOk =
        cons.root_to === head2.root &&
        (await verifyConsistency(signedSize, currentSize, cons.proof, merkleRoot, cons.root_to))
    } else {
      // Same size: the presented head must be byte-for-byte the signed root, or it was rewritten.
      consistencyOk = head2.root === merkleRoot
    }
    return { state: 'done', inclusionOk, consistencyOk, signedSize, currentSize, grew }
  } catch (e) {
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}

export function ProofVerifier() {
  const { subjectId: routeSubject } = useParams()
  const navigate = useNavigate()
  const [input, setInput] = useState(routeSubject ?? '')
  const [status, setStatus] = useState<Status>({ kind: 'idle' })
  // Staleness guard: only the newest in-flight check may write state, so a slow response for a
  // previous subject can never overwrite the verdict for the current one.
  const generation = useRef(0)

  const check = useCallback(async (rawSubject: string) => {
    // Subject ids are canonical lowercase UUIDs and the binding hash is case-sensitive; normalize
    // so a pasted uppercase id does not false-alarm as a mismatch.
    const subject = rawSubject.trim().toLowerCase()
    const gen = ++generation.current
    const put = (s: Status) => {
      if (generation.current === gen) {
        setStatus(s)
      }
    }
    put({ kind: 'loading' })

    let proof: ProofView
    try {
      proof = await getClient().getProof(subject)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        put({ kind: 'notfound' })
      } else {
        put({ kind: 'error', message: e instanceof Error ? e.message : String(e) })
      }
      return
    }
    if (!proof.proof_body || !proof.proof_signature || !proof.signer_pubkey_pem) {
      put({ kind: 'pending', proof })
      return
    }

    const bodyBytes = new TextEncoder().encode(proof.proof_body)
    let ok: boolean
    let body: Record<string, unknown>
    let keyFingerprint: string
    try {
      ok = await verifyProofSignature(bodyBytes, proof.proof_signature, proof.signer_pubkey_pem)
      body = JSON.parse(proof.proof_body) as Record<string, unknown>
      keyFingerprint = await sha256Hex(pemToDer(proof.signer_pubkey_pem))
    } catch (e) {
      // Undecodable signature/key/body: distinct from a signature that cleanly fails to verify.
      put({
        kind: 'malformed',
        message: `proof data could not be decoded (${e instanceof Error ? e.message : String(e)})`,
      })
      return
    }
    if (!ok) {
      put({ kind: 'failed' })
      return
    }

    // Subject binding: a valid signature alone only proves the server HAS a signed proof. Require
    // the signed body to name this URL's subject, or a compromised server could replay one real
    // proof for every subject.
    const wantHash = await sha256Hex(new TextEncoder().encode(subject))
    const gotHash = String(body.subject_hash ?? '')
    if (gotHash !== wantHash) {
      put({ kind: 'mismatch', wantHash, gotHash })
      return
    }

    const bodySha256 = await sha256Hex(bodyBytes)
    put({ kind: 'verified', proof, body, bodySha256, keyFingerprint, transparency: { state: 'checking' } })
    // The transparency proofs need extra fetches; run them after the signature verdict and fold the
    // result in (guarded by the generation counter so a stale check never overwrites a newer one).
    const transparency = await checkTransparency(body, getClient())
    put({ kind: 'verified', proof, body, bodySha256, keyFingerprint, transparency })
  }, [])

  useEffect(() => {
    if (routeSubject) {
      setInput(routeSubject)
      void check(routeSubject)
    } else {
      generation.current++
      setStatus({ kind: 'idle' })
    }
  }, [routeSubject, check])

  const submit = () => {
    const s = input.trim()
    if (s) {
      void navigate(`/proof/${encodeURIComponent(s)}`)
    }
  }

  return (
    <div className="prose">
      <h1>Verify an erasure proof</h1>
      <p className="lead">
        The checks run in YOUR browser with WebCrypto: the ECDSA signature over the exact signed
        bytes, and that the signed document names this subject (its subject_hash must equal the
        SHA-256 of the subject id you asked about).
      </p>

      <div className="stage__actions">
        <input
          className="verifier__input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="subject id (uuid)"
          aria-label="subject id"
        />
        <button className="btn btn--accent" onClick={submit} disabled={!input.trim()}>
          Verify
        </button>
      </div>

      {status.kind === 'loading' && <div className="note">Fetching and verifying...</div>}
      {status.kind === 'notfound' && (
        <div className="note">No erasure record for that subject. Run an erasure in the demo first.</div>
      )}
      {status.kind === 'error' && <div className="note note--error">{status.message}</div>}
      {status.kind === 'malformed' && (
        <div className="note note--error">
          MALFORMED PROOF DATA: {status.message}. This means corruption or tampering of the stored
          proof, not a failed signature check.
        </div>
      )}
      {status.kind === 'pending' && (
        <div className="note">
          The erasure is committed but its proof is not anchored yet (the reconciler retries
          anchoring). Check again shortly.
        </div>
      )}
      {status.kind === 'failed' && (
        <div className="note note--error">
          SIGNATURE INVALID: the proof document does not match its signature. Either the stored
          proof was tampered with or it was corrupted; both are exactly what this check exists to
          catch.
        </div>
      )}
      {status.kind === 'mismatch' && (
        <div className="note note--error">
          VALID SIGNATURE, WRONG SUBJECT: the signed document names subject_hash {status.gotHash},
          but SHA-256 of this subject id is {status.wantHash}. A validly signed proof for a
          different subject proves nothing about this one (replay).
        </div>
      )}

      {status.kind === 'verified' && (
        <>
          <div className="verifier__verdict">SIGNATURE VERIFIED</div>
          <div className="verifier__actions">
            <button className="btn btn--small" onClick={() => downloadProof(status.proof)}>
              Download the signed proof (.json)
            </button>
          </div>
          <KeyValue items={signedItems(status)} />
          <div className="note">
            Server-asserted (not covered by the signature): committed{' '}
            {status.proof.committed_at ?? '(pending)'}; recorded S3 anchor{' '}
            <span className="mono">{status.proof.proof_ref ?? '(pending)'}</span>, which you can
            fetch and compare against the proof digest independently.
          </div>
          {transparencyPanel(status.transparency)}
          <CodeBlock>{formatBody(status.proof.proof_body ?? '')}</CodeBlock>
          <div className="note">
            Trust anchor, stated honestly: this page receives the public key alongside the proof, so
            a compromised server could swap both together. The independent checks are the signed
            subject binding above, the S3 Object Lock copy, and the signer-key fingerprint, compare
            it across proofs and against the published key. In production the verifier key is
            distributed out of band.
          </div>
        </>
      )}
    </div>
  )
}

// downloadProof saves the erasure proof as the judge takes it away: the exact signed canonical
// bytes, the signature, and the signer public key, so anyone can re-verify offline against the
// same code the page runs. This is the erasure certificate, the delivered artifact.
function downloadProof(proof: ProofView) {
  const doc = {
    proof: proof.proof_body ? JSON.parse(proof.proof_body) : null,
    proof_canonical: proof.proof_body, // the exact bytes the signature covers
    signature_b64: proof.proof_signature,
    signer_public_key_pem: proof.signer_pubkey_pem,
    proof_ref: proof.proof_ref,
    committed_at: proof.committed_at,
  }
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `erasure-proof-${proof.subject_id}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function transparencyPanel(t: Transparency) {
  if (t.state === 'unavailable') {
    return (
      <div className="note">
        Transparency-log check: this proof predates the RFC 6962 tree fields, so browser inclusion
        and consistency verification is not available for it.
      </div>
    )
  }
  if (t.state === 'checking') {
    return <div className="note">Transparency-log check: verifying inclusion and consistency...</div>
  }
  if (t.state === 'error') {
    return <div className="note note--error">Transparency-log check failed: {t.message}</div>
  }
  return (
    <>
      <KeyValue
        items={[
          {
            k: 'included in the signed tree',
            v: t.inclusionOk ? `yes, leaf of tree size ${t.signedSize}` : 'NO',
            tone: t.inclusionOk ? 'ok' : 'bad',
          },
          {
            k: 'log is append-only since',
            v: t.consistencyOk
              ? t.grew
                ? `yes, extended ${t.signedSize} to ${t.currentSize}, never rewritten`
                : 'yes, head still matches the signed root'
              : t.currentSize < t.signedSize
                ? `NO, the served log (size ${t.currentSize}) is smaller than the signed tree`
                : 'NO, consistency check failed',
            tone: t.consistencyOk ? 'ok' : 'bad',
          },
        ]}
      />
      <div className="note">
        Verified in your browser: the erasure&apos;s decision-log entry is a leaf of the exact tree
        this signature committed to (leaf recomputed from the signed head, checked against the signed
        root), and the current log is a consistent, append-only extension of it. The signed root is a
        snapshot; the consistency proof shows the log only grew.
      </div>
    </>
  )
}

function signedItems(s: Extract<Status, { kind: 'verified' }>): KV[] {
  const field = (k: string) => String(s.body[k] ?? '(absent)')
  return [
    { k: 'subject binding', v: 'subject_hash matches SHA-256(subject id)', tone: 'ok' },
    { k: 'subject', v: s.proof.subject_id },
    { k: 'decision_log seq', v: field('decision_log_seq') },
    { k: 'occurred (signed)', v: field('occurred_at') },
    { k: 'key state (signed)', v: field('kms_key_state') !== '(absent)' ? field('kms_key_state') : field('key_state') },
    { k: 'proof sha-256', v: s.bodySha256 },
    { k: 'signer key sha-256', v: s.keyFingerprint },
  ]
}

function formatBody(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    return body
  }
}
