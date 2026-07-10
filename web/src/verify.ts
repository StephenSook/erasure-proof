// Browser-side proof verification with WebCrypto. The signature is checked over the EXACT canonical
// bytes stored at anchor time (never re-canonicalized here), with the ECDSA P-256 public key
// imported from PEM. Runs entirely in the visitor's browser: no trust in our server required for
// the check itself (the honest trust-anchor note lives on the page).

// Uint8Array<ArrayBuffer> (not ArrayBufferLike) so the values satisfy WebCrypto's BufferSource
// under TypeScript 5.9's stricter typed-array generics.
export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64)
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i)
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Extract the DER bytes from a PEM public key. */
export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '')
  if (body.length === 0) {
    throw new Error('empty PEM body')
  }
  return b64ToBytes(body)
}

/**
 * Convert a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs, what pyca/cryptography emits)
 * to the raw 64-byte r||s form WebCrypto expects. A 64-byte input is assumed to already be raw.
 */
export function toRawSignature(sig: Uint8Array): Uint8Array<ArrayBuffer> {
  if (sig.length === 64) {
    const copy = new Uint8Array(new ArrayBuffer(64))
    copy.set(sig)
    return copy
  }
  if (sig[0] !== 0x30) {
    throw new Error('signature is neither raw r||s nor DER')
  }
  let offset = 2 // SEQUENCE tag + short length (P-256 sigs are < 128 bytes total)
  if (sig[1] & 0x80) {
    offset = 2 + (sig[1] & 0x7f) // long-form length: skip the length-of-length bytes
  }
  const readInt = (): Uint8Array => {
    if (sig[offset] !== 0x02) {
      throw new Error('malformed DER signature: expected INTEGER')
    }
    const len = sig[offset + 1]
    let start = offset + 2
    let n = len
    // Strip leading zero padding (DER sign byte); the value itself is at most 32 bytes.
    while (n > 32 && sig[start] === 0x00) {
      start++
      n--
    }
    if (n > 32) {
      throw new Error('malformed DER signature: integer wider than 32 bytes')
    }
    offset = offset + 2 + len
    const out = new Uint8Array(32)
    out.set(sig.slice(start, start + n), 32 - n) // left-pad to 32
    return out
  }
  const r = readInt()
  const s = readInt()
  const raw = new Uint8Array(new ArrayBuffer(64))
  raw.set(r, 0)
  raw.set(s, 32)
  return raw
}

/** Verify an ECDSA P-256 / SHA-256 signature over the exact body bytes. */
export async function verifyProofSignature(
  bodyBytes: Uint8Array,
  signatureB64: string,
  publicKeyPem: string,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'spki',
    pemToDer(publicKeyPem),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const raw = toRawSignature(b64ToBytes(signatureB64))
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, toPlainBuffer(bodyBytes))
}

/** SHA-256 hex digest of bytes (for displaying the proof digest and the signer-key fingerprint). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toPlainBuffer(bytes))
  return bytesToHex(new Uint8Array(digest))
}

/** Copy any Uint8Array (whatever its backing buffer type) into a plain ArrayBuffer-backed one. */
function toPlainBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length))
  out.set(bytes)
  return out
}
