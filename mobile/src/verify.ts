// Offline verification of an erasure proof, entirely on device. Mirrors the web verifier
// (web/src/verify.ts) but with zero platform crypto: @noble/curves does P-256 ECDSA in pure JS, so
// it runs in React Native / Hermes with no native module and no network. Verification needs no
// randomness, so no getRandomValues polyfill is required.
//
// TRUST MODEL (stated as honestly here as on the web /proof page). The signature proves the
// certificate is internally consistent and untampered under WHATEVER key is presented. It does NOT
// prove the signer is legitimate: anyone can generate a key, sign a fabricated certificate, and
// present their own key. So we (1) verify against the key EMBEDDED in the signed bytes (the one the
// signature commits to), not an unsigned outer field, and (2) check that key's fingerprint against
// a list of KNOWN_SIGNERS. A recognized signer is reported trusted; an unrecognized one is reported
// as a valid-signature-but-unverified-signer, with the fingerprint to compare out of band. The UI
// must never present a bare "verified" badge as proof of authenticity on its own.
//
// lowS:false matches the pyca/KMS and WebCrypto signer (neither enforces low-S). prehash:false
// because we pass the SHA-256 digest ourselves. format:'der' because the signer emits DER.

import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

// Signers this build recognizes. The demo signer is bundled so the demo certificate reads as
// trusted; add the production KMS signing key fingerprint here at deploy (its fingerprint is shown
// on the web /trust page and in every proof).
export interface KnownSigner {
  fingerprint: string
  label: string
}
export const KNOWN_SIGNERS: KnownSigner[] = [
  { fingerprint: 'e170f6776956655c', label: 'erasure-proof demo signer' },
]

// The downloaded proof file shape (web /proof "Download the signed proof").
export interface ProofFile {
  proof_canonical?: string
  signature_b64?: string
  signer_public_key_pem?: string
  proof?: Record<string, unknown>
  proof_ref?: string | null
  committed_at?: string | null
}

export type VerifyResult =
  | {
      kind: 'verified'
      facts: Record<string, unknown>
      signerFingerprint: string
      signerTrusted: boolean
      signerLabel?: string
    }
  | { kind: 'invalid' } // well-formed but the signature does not verify
  | { kind: 'malformed'; message: string } // undecodable input

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const B64_LOOKUP = (() => {
  const t = new Int16Array(256).fill(-1)
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i
  return t
})()

// Strict base64 decode. Accepts standard and URL-safe alphabets; throws on any invalid character or
// bad length, so a malformed signature/key lands in the 'malformed' path rather than silently
// decoding to wrong bytes.
function base64ToBytes(input: string): Uint8Array {
  let s = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  const pad = s.length % 4
  if (pad === 1) throw new Error('bad base64 length')
  if (pad) s += '='.repeat(4 - pad)
  const outLen = (s.length / 4) * 3 - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0)
  const bytes = new Uint8Array(outLen)
  let p = 0
  for (let i = 0; i < s.length; i += 4) {
    const c0 = s.charCodeAt(i)
    const c1 = s.charCodeAt(i + 1)
    const c2 = s.charCodeAt(i + 2)
    const c3 = s.charCodeAt(i + 3)
    const a = B64_LOOKUP[c0]
    const b = B64_LOOKUP[c1]
    const cPad = c2 === 0x3d // '='
    const dPad = c3 === 0x3d
    const c = cPad ? 0 : B64_LOOKUP[c2]
    const d = dPad ? 0 : B64_LOOKUP[c3]
    if (a < 0 || b < 0 || c < 0 || d < 0) throw new Error('bad base64 character')
    const n = (a << 18) | (b << 12) | (c << 6) | d
    bytes[p++] = (n >> 16) & 0xff
    if (!cPad) bytes[p++] = (n >> 8) & 0xff
    if (!dPad) bytes[p++] = n & 0xff
  }
  return bytes
}

// Deterministic UTF-8 encoder (no dependency on a TextEncoder global across Hermes versions).
function utf8ToBytes(str: string): Uint8Array {
  const out: number[] = []
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    if (c < 0x80) out.push(c)
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = str.charCodeAt(++i)
      c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff)
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
  }
  return Uint8Array.from(out)
}

function bytesToHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

function fingerprintOf(pem: string): string {
  return bytesToHex(sha256(utf8ToBytes(pem))).slice(0, 16)
}

// The uncompressed EC point (0x04 || X32 || Y32 = 65 bytes) is the trailing 65 bytes of a P-256
// SPKI DER. noble validates the point is on the curve during verify, so a wrong-but-0x04 trailing
// slice is rejected (off-curve throws, caught as invalid) rather than accepted.
function spkiToPoint(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  const der = base64ToBytes(b64)
  if (der.length < 65) throw new Error('SPKI too short')
  const point = der.slice(der.length - 65)
  if (point[0] !== 0x04) throw new Error('not an uncompressed P-256 public key')
  return point
}

export function verifyProof(file: ProofFile): VerifyResult {
  const { proof_canonical, signature_b64 } = file
  if (!proof_canonical || !signature_b64) {
    return { kind: 'malformed', message: 'proof file is missing the signed bytes or the signature' }
  }
  let facts: Record<string, unknown>
  let der: Uint8Array
  let verifyPem: string
  let point: Uint8Array
  let msgHash: Uint8Array
  try {
    facts = JSON.parse(proof_canonical) as Record<string, unknown>
    // Verify against the key the signature COMMITS to (embedded in the signed bytes), not an
    // unsigned outer field. Fall back to the outer field only if the signed bytes carry no key.
    const embedded = typeof facts.signer_public_key === 'string' ? facts.signer_public_key : undefined
    verifyPem = embedded ?? file.signer_public_key_pem ?? ''
    if (!verifyPem) return { kind: 'malformed', message: 'proof carries no signer public key' }
    der = base64ToBytes(signature_b64)
    point = spkiToPoint(verifyPem)
    msgHash = sha256(utf8ToBytes(proof_canonical))
  } catch (e) {
    return { kind: 'malformed', message: e instanceof Error ? e.message : String(e) }
  }
  let ok = false
  try {
    ok = p256.verify(der, msgHash, point, { format: 'der', prehash: false, lowS: false })
  } catch {
    return { kind: 'invalid' } // an unparseable signature or off-curve key is a failed verification
  }
  if (!ok) return { kind: 'invalid' }
  const fingerprint = fingerprintOf(verifyPem)
  const known = KNOWN_SIGNERS.find((s) => s.fingerprint === fingerprint)
  return {
    kind: 'verified',
    facts,
    signerFingerprint: fingerprint,
    signerTrusted: known !== undefined,
    signerLabel: known?.label,
  }
}
