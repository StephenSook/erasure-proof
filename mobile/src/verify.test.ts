// Parity + regression + adversarial tests for the offline verifier. The demo certificate was signed
// by the real cryptod signer (ECDSA P-256, DER, over canonical bytes), so a passing parity test
// proves this pure-JS verifier agrees with the backend byte-for-byte. The adversarial tests prove
// the trust model: a valid signature by an unknown key verifies but is NOT trusted, a high-S
// signature is accepted (parity with pyca/KMS, which do not enforce low-S), and the embedded signer
// key cannot be swapped without breaking the signature. Run with: npm test (tsx --test).

import assert from 'node:assert/strict'
import { createSign, generateKeyPairSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { type ProofFile, verifyProof } from './verify.ts'

const demo = JSON.parse(
  readFileSync(fileURLToPath(new URL('../assets/demo-proof.json', import.meta.url)), 'utf8'),
) as ProofFile

// A different but well-formed P-256 SPKI PEM (a fresh key), used to prove the top-level field is
// ignored in favor of the key bound inside the signed bytes.
const otherPem =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n' +
  'q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n' +
  '-----END PUBLIC KEY-----\n'

// P-256 group order n, for the high-S malleability test.
const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')

test('verifies a genuine signed certificate offline and reports the bundled demo signer as trusted', () => {
  const r = verifyProof(demo)
  assert.equal(r.kind, 'verified')
  if (r.kind === 'verified') {
    assert.equal(r.facts.decision_log_seq, 42)
    assert.equal(r.facts.type, 'erasure-proof')
    assert.match(r.signerFingerprint, /^[0-9a-f]{16}$/)
    assert.equal(r.signerTrusted, true)
    assert.equal(r.signerLabel, 'erasure-proof demo signer')
  }
})

test('rejects a tampered certificate (one byte changed in the signed bytes)', () => {
  const tampered: ProofFile = {
    ...demo,
    proof_canonical: demo.proof_canonical!.replace('"tree_size":128', '"tree_size":1'),
  }
  assert.equal(verifyProof(tampered).kind, 'invalid')
})

test('rejects a reserialized certificate (whitespace changes the signed bytes)', () => {
  const reserialized: ProofFile = {
    ...demo,
    proof_canonical: demo.proof_canonical!.replace('{', '{ '),
  }
  assert.equal(verifyProof(reserialized).kind, 'invalid')
})

test('verifies via the EMBEDDED signer key, ignoring a mismatched top-level pem', () => {
  // The signature commits to the key inside proof_canonical, so an attacker cannot substitute a
  // different outer signer_public_key_pem to change what the signature appears to attest.
  const r = verifyProof({ ...demo, signer_public_key_pem: otherPem })
  assert.equal(r.kind, 'verified')
  if (r.kind === 'verified') assert.equal(r.signerTrusted, true)
})

test('a valid signature by an UNKNOWN key verifies but is NOT trusted (trust-anchor / forgery guard)', () => {
  // A fully self-consistent certificate signed by an attacker's own fresh key. The signature is
  // valid over its bytes, so kind is 'verified'; but the signer is not a known one, so signerTrusted
  // must be false. This is the whole point of the trust anchor: a valid signature is not authenticity.
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const forged = {
    type: 'erasure-proof',
    subject_hash: 'ff'.repeat(32),
    decision_log_seq: 999,
    occurred_at: '2026-01-01T00:00:00Z',
    signer_public_key: pem,
  }
  const canonical = JSON.stringify(forged)
  const sig = createSign('SHA256').update(canonical).end().sign(privateKey) // DER by default for EC
  const file: ProofFile = {
    proof_canonical: canonical,
    signature_b64: sig.toString('base64'),
    signer_public_key_pem: pem,
  }
  const r = verifyProof(file)
  assert.equal(r.kind, 'verified')
  if (r.kind === 'verified') {
    assert.equal(r.signerTrusted, false)
    assert.equal(r.signerLabel, undefined)
  }
})

test('accepts the high-S counterpart signature (lowS:false parity with pyca/KMS)', () => {
  // ECDSA is malleable: (r, s) and (r, n - s) are both valid. pyca/cryptography and AWS KMS emit
  // whichever they compute and do NOT enforce low-S, so the verifier must accept high-S. Force the
  // high-S variant and require it verify; with the lowS default (true) this would fail.
  const der = new Uint8Array(Buffer.from(demo.signature_b64!, 'base64'))
  const { r, s } = parseDerSig(der)
  const sHigh = s > N >> 1n ? s : N - s
  const malleated = encodeDerSig(r, sHigh)
  const file: ProofFile = { ...demo, signature_b64: Buffer.from(malleated).toString('base64') }
  assert.equal(verifyProof(file).kind, 'verified')
})

test('rejects a certificate whose embedded signer key was swapped', () => {
  const facts = JSON.parse(demo.proof_canonical!) as Record<string, unknown>
  facts.signer_public_key = otherPem
  const swapped: ProofFile = { ...demo, proof_canonical: JSON.stringify(facts) }
  assert.notEqual(verifyProof(swapped).kind, 'verified')
})

test('rejects a well-formed base64 signature that is not valid DER', () => {
  const file: ProofFile = { ...demo, signature_b64: Buffer.from(new Uint8Array(16)).toString('base64') }
  assert.equal(verifyProof(file).kind, 'invalid')
})

test('flags a malformed file (missing signed bytes)', () => {
  assert.equal(verifyProof({ proof_canonical: demo.proof_canonical }).kind, 'malformed')
})

test('flags undecodable base64 as malformed, not a crash', () => {
  const bad: ProofFile = { ...demo, signature_b64: 'not-base64-!!!' }
  const r = verifyProof(bad)
  assert.ok(r.kind === 'malformed' || r.kind === 'invalid')
})

// --- minimal DER ECDSA (SEQUENCE of two INTEGERs) helpers, single-byte lengths (P-256 fits) ---

function parseDerSig(der: Uint8Array): { r: bigint; s: bigint } {
  let i = 2 // skip SEQUENCE tag (0x30) + length
  if (der[i] !== 0x02) throw new Error('expected INTEGER r')
  i++
  const rlen = der[i]
  i++
  const r = BigInt('0x' + Buffer.from(der.slice(i, i + rlen)).toString('hex'))
  i += rlen
  if (der[i] !== 0x02) throw new Error('expected INTEGER s')
  i++
  const slen = der[i]
  i++
  const s = BigInt('0x' + Buffer.from(der.slice(i, i + slen)).toString('hex'))
  return { r, s }
}

function derInt(x: bigint): number[] {
  let hex = x.toString(16)
  if (hex.length % 2) hex = '0' + hex
  let bytes = (hex.match(/../g) ?? []).map((h) => parseInt(h, 16))
  while (bytes.length > 1 && bytes[0] === 0) bytes.shift()
  if (bytes[0] & 0x80) bytes = [0, ...bytes]
  return [0x02, bytes.length, ...bytes]
}

function encodeDerSig(r: bigint, s: bigint): Uint8Array {
  const body = [...derInt(r), ...derInt(s)]
  return Uint8Array.from([0x30, body.length, ...body])
}
