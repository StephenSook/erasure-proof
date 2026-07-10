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

// Fails loudly on malformed input (odd length, non-hex characters) instead of coercing NaN to
// zero bytes, so a transport/encoding bug is distinguishable from a genuine exclusion.
export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('malformed hex string')
  }
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2))
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toPlainBuffer(bytes)))
}

/** RFC 6962 leaf hash: SHA-256(0x00 || leaf). */
export async function merkleLeafHash(leaf: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + leaf.length)
  buf[0] = 0x00
  buf.set(leaf, 1)
  return sha256(buf)
}

/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export async function merkleNodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + left.length + right.length)
  buf[0] = 0x01
  buf.set(left, 1)
  buf.set(right, 1 + left.length)
  return sha256(buf)
}

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1
  while (k < n) {
    k <<= 1
  }
  return k >> 1
}

// Recompute the root from a leaf hash, mirroring the Go merkle.computeRoot exactly (same split and
// path ordering), which stays correct for unbalanced RFC 6962 trees where naive index-bit walking
// is wrong.
async function computeRoot(
  leafHash: Uint8Array,
  m: number,
  n: number,
  path: Uint8Array[],
): Promise<Uint8Array | null> {
  if (n === 1) {
    return path.length === 0 ? leafHash : null
  }
  if (path.length === 0) {
    return null
  }
  const sibling = path[path.length - 1]
  const rest = path.slice(0, -1)
  const k = largestPowerOfTwoLessThan(n)
  if (m < k) {
    const left = await computeRoot(leafHash, m, k, rest)
    return left && merkleNodeHash(left, sibling)
  }
  const right = await computeRoot(leafHash, m - k, n - k, rest)
  return right && merkleNodeHash(sibling, right)
}

/**
 * Verify an RFC 6962 inclusion proof entirely in the browser: that the leaf at leafIndex is in the
 * Merkle tree of the given size and root. All arguments are hex. This lets a verifier confirm a
 * decision-log entry is included in the tree a signed erasure proof committed to.
 *
 * Soundness contract (mirrors the Go VerifyInclusion): leafHashHex must be recomputed by THIS
 * verifier via merkleLeafHash from the row's own chain hash, never taken from the server asserting
 * inclusion, and treeSize must come from the SIGNED proof, not from the endpoint that supplied the
 * audit path. The signed root is a snapshot at anchor time; after later log appends the live tree
 * diverges, so verify against the signed (root, tree_size), then use verifyConsistency to show the
 * current tree is an append-only extension of that snapshot.
 * Every hash must be exactly 32 bytes (64 hex chars): without the width guard, a spliced
 * over-length "leaf" plus a short sibling can reconstruct a genuine root from non-leaf data.
 */
export async function verifyInclusion(
  leafHashHex: string,
  leafIndex: number,
  treeSize: number,
  auditPathHex: string[],
  rootHex: string,
): Promise<boolean> {
  if (leafIndex < 0 || leafIndex >= treeSize) {
    return false
  }
  if (leafHashHex.length !== 64 || auditPathHex.some((p) => p.length !== 64)) {
    return false
  }
  const computed = await computeRoot(
    hexToBytes(leafHashHex),
    leafIndex,
    treeSize,
    auditPathHex.map(hexToBytes),
  )
  return computed !== null && bytesToHex(computed) === rootHex.toLowerCase()
}

// --- RFC 6962 consistency proof (browser verifier, mirrors the Go merkle.VerifyConsistency) ---

function trailingZeros(x: number): number {
  if (x === 0) return 0
  let n = 0
  while ((x & 1) === 0) {
    n++
    x >>>= 1
  }
  return n
}

function bitLen(x: number): number {
  let n = 0
  while (x > 0) {
    n++
    x = Math.floor(x / 2)
  }
  return n
}

function onesCount(x: number): number {
  let c = 0
  while (x > 0) {
    c += x & 1
    x >>>= 1
  }
  return c
}

async function chainInner(seed: Uint8Array, proof: Uint8Array[], index: number): Promise<Uint8Array> {
  let acc = seed
  for (let i = 0; i < proof.length; i++) {
    acc = ((index >>> i) & 1) === 0 ? await merkleNodeHash(acc, proof[i]) : await merkleNodeHash(proof[i], acc)
  }
  return acc
}

async function chainInnerRight(
  seed: Uint8Array,
  proof: Uint8Array[],
  index: number,
): Promise<Uint8Array> {
  let acc = seed
  for (let i = 0; i < proof.length; i++) {
    if (((index >>> i) & 1) === 1) {
      acc = await merkleNodeHash(proof[i], acc)
    }
  }
  return acc
}

async function chainBorderRight(seed: Uint8Array, proof: Uint8Array[]): Promise<Uint8Array> {
  let acc = seed
  for (const h of proof) {
    acc = await merkleNodeHash(h, acc)
  }
  return acc
}

/**
 * Verify an RFC 6962 consistency proof entirely in the browser: that the tree of size sizeFrom with
 * rootFrom is an append-only prefix of the tree of size sizeTo with rootTo (the log only grew, was
 * never rewritten). All hash arguments are hex. Reconstructs BOTH roots from the proof and checks
 * each. This lets a verifier confirm the current decision log extends the exact tree an older signed
 * erasure proof committed to.
 */
export async function verifyConsistency(
  sizeFrom: number,
  sizeTo: number,
  proofHex: string[],
  rootFromHex: string,
  rootToHex: string,
): Promise<boolean> {
  if (sizeFrom <= 0 || sizeFrom > sizeTo) return false
  if (rootFromHex.length !== 64 || rootToHex.length !== 64) return false
  if (proofHex.some((p) => p.length !== 64)) return false
  const rootFrom = rootFromHex.toLowerCase()
  const rootTo = rootToHex.toLowerCase()
  if (sizeFrom === sizeTo) {
    return proofHex.length === 0 && rootFrom === rootTo
  }
  if (proofHex.length === 0) return false

  const inner0 = bitLen((sizeFrom - 1) ^ (sizeTo - 1))
  const border = onesCount((sizeFrom - 1) >>> inner0)
  const shift = trailingZeros(sizeFrom)
  const inner = inner0 - shift

  let seed: Uint8Array
  let start: number
  if (sizeFrom === 1 << shift) {
    seed = hexToBytes(rootFromHex)
    start = 0
  } else {
    seed = hexToBytes(proofHex[0])
    start = 1
  }
  if (proofHex.length !== start + inner + border) return false

  const proof = proofHex.slice(start).map(hexToBytes)
  const mask = (sizeFrom - 1) >>> shift
  const innerProof = proof.slice(0, inner)
  const borderProof = proof.slice(inner)

  const hash1 = await chainBorderRight(await chainInnerRight(seed, innerProof, mask), borderProof)
  const hash2 = await chainBorderRight(await chainInner(seed, innerProof, mask), borderProof)
  return bytesToHex(hash1) === rootFrom && bytesToHex(hash2) === rootTo
}

/** Copy any Uint8Array (whatever its backing buffer type) into a plain ArrayBuffer-backed one. */
function toPlainBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length))
  out.set(bytes)
  return out
}
