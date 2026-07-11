// Offline verification of an erasure proof, entirely on device. Mirrors the web verifier
// (web/src/verify.ts) but with zero platform crypto: @noble/curves does P-256 ECDSA in pure JS, so
// it runs in React Native / Hermes with no native module and no network. Verification needs no
// randomness, so no getRandomValues polyfill is required.
//
// The signature covers the EXACT canonical bytes (proof_canonical). We display facts parsed from
// THOSE signed bytes, never from a separate unsigned field, so what the verdict covers is what the
// screen shows. lowS:false matches the pyca/KMS and WebCrypto signer (neither enforces low-S);
// prehash:false because we pass the SHA-256 digest ourselves; format:'der' because the signer
// (pyca cryptography / AWS KMS) emits DER-encoded ECDSA signatures.

import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

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
  | { kind: 'verified'; facts: Record<string, unknown>; signerFingerprint: string }
  | { kind: 'invalid' } // well-formed but the signature does not verify
  | { kind: 'malformed'; message: string } // undecodable input

function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '')
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const lookup = new Int16Array(256).fill(-1)
  for (let i = 0; i < alphabet.length; i++) lookup[alphabet.charCodeAt(i)] = i
  const len = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0
  const bytes = new Uint8Array((clean.length / 4) * 3 - len)
  let p = 0
  for (let i = 0; i < clean.length; i += 4) {
    const a = lookup[clean.charCodeAt(i)]
    const b = lookup[clean.charCodeAt(i + 1)]
    const c = lookup[clean.charCodeAt(i + 2)]
    const d = lookup[clean.charCodeAt(i + 3)]
    if (a < 0 || b < 0) throw new Error('bad base64')
    const n = (a << 18) | (b << 12) | ((c < 0 ? 0 : c) << 6) | (d < 0 ? 0 : d)
    bytes[p++] = (n >> 16) & 0xff
    if (c >= 0) bytes[p++] = (n >> 8) & 0xff
    if (d >= 0) bytes[p++] = n & 0xff
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
      // surrogate pair
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

// The uncompressed EC point (0x04 || X32 || Y32 = 65 bytes) is the trailing 65 bytes of a P-256
// SPKI DER. Extract it for noble (which takes the raw point), matching what WebCrypto importKey does.
function spkiToPoint(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  const der = base64ToBytes(b64)
  if (der.length < 65) throw new Error('SPKI too short')
  const point = der.slice(der.length - 65)
  if (point[0] !== 0x04) throw new Error('not an uncompressed P-256 public key')
  return point
}

export function verifyProof(file: ProofFile): VerifyResult {
  const { proof_canonical, signature_b64, signer_public_key_pem } = file
  if (!proof_canonical || !signature_b64 || !signer_public_key_pem) {
    return { kind: 'malformed', message: 'proof file is missing signed bytes, signature, or key' }
  }
  let der: Uint8Array
  let point: Uint8Array
  let msgHash: Uint8Array
  let facts: Record<string, unknown>
  let fingerprint: string
  try {
    der = base64ToBytes(signature_b64)
    point = spkiToPoint(signer_public_key_pem)
    msgHash = sha256(utf8ToBytes(proof_canonical))
    // Facts come from the SIGNED bytes, so the screen shows only what the signature covers.
    facts = JSON.parse(proof_canonical) as Record<string, unknown>
    fingerprint = bytesToHex(sha256(utf8ToBytes(signer_public_key_pem))).slice(0, 16)
  } catch (e) {
    return { kind: 'malformed', message: e instanceof Error ? e.message : String(e) }
  }
  let ok = false
  try {
    ok = p256.verify(der, msgHash, point, { format: 'der', prehash: false, lowS: false })
  } catch {
    return { kind: 'invalid' } // an unparseable signature is a failed verification, not a crash
  }
  return ok ? { kind: 'verified', facts, signerFingerprint: fingerprint } : { kind: 'invalid' }
}
