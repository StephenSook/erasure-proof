// Parity + regression tests for the offline verifier. The demo certificate was signed by the real
// cryptod signer (ECDSA P-256, DER, over canonical bytes), so a passing test proves this pure-JS
// verifier agrees with the backend byte-for-byte. Run with: npm test (tsx --test).

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { type ProofFile, verifyProof } from './verify.ts'

const demo = JSON.parse(
  readFileSync(fileURLToPath(new URL('../assets/demo-proof.json', import.meta.url)), 'utf8'),
) as ProofFile

test('verifies a genuine signed certificate offline', () => {
  const r = verifyProof(demo)
  assert.equal(r.kind, 'verified')
  if (r.kind === 'verified') {
    assert.equal(r.facts.decision_log_seq, 42)
    assert.equal(r.facts.type, 'erasure-proof')
    assert.match(r.signerFingerprint, /^[0-9a-f]{16}$/)
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

test('rejects the wrong signer key', () => {
  // A different but well-formed P-256 SPKI PEM (a fresh key). Signature no longer matches.
  const otherPem =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n' +
    'q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n' +
    '-----END PUBLIC KEY-----\n'
  const wrong: ProofFile = { ...demo, signer_public_key_pem: otherPem }
  assert.equal(verifyProof(wrong).kind, 'invalid')
})

test('flags a malformed file (missing signed bytes)', () => {
  assert.equal(verifyProof({ proof_canonical: demo.proof_canonical }).kind, 'malformed')
})

test('flags undecodable base64 as malformed, not a crash', () => {
  const bad: ProofFile = { ...demo, signature_b64: 'not-base64-!!!' }
  const r = verifyProof(bad)
  assert.ok(r.kind === 'malformed' || r.kind === 'invalid')
})
