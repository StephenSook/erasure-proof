import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ApiError, getClient, type ProofView } from '../api'
import { CodeBlock } from '../components/CodeBlock'
import { KeyValue, type KV } from '../components/KeyValue'
import { pemToDer, sha256Hex, verifyProofSignature } from '../verify'

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

    put({ kind: 'verified', proof, body, bodySha256: await sha256Hex(bodyBytes), keyFingerprint })
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
          <KeyValue items={signedItems(status)} />
          <div className="note">
            Server-asserted (not covered by the signature): committed{' '}
            {status.proof.committed_at ?? '(pending)'}; recorded S3 anchor{' '}
            <span className="mono">{status.proof.proof_ref ?? '(pending)'}</span>, which you can
            fetch and compare against the proof digest independently.
          </div>
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
