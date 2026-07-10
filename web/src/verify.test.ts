import { describe, expect, it } from 'vitest'
import { b64ToBytes, bytesToHex, merkleLeafHash, merkleNodeHash, pemToDer, sha256Hex, toRawSignature, verifyInclusion, verifyProofSignature } from './verify'

// These tests exercise the real WebCrypto implementation (Node's webcrypto under vitest): generate
// a P-256 key, sign, and drive the exact code path the browser runs.

function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) {
    bin += String.fromCharCode(b)
  }
  return btoa(bin)
}

function spkiToPem(spki: ArrayBuffer): string {
  const b64 = bytesToB64(new Uint8Array(spki))
  const lines = b64.match(/.{1,64}/g) ?? []
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`
}

/** Encode a raw r||s signature into DER, mimicking what pyca/cryptography emits. */
function rawToDer(raw: Uint8Array): Uint8Array {
  const encodeInt = (v: Uint8Array): number[] => {
    let i = 0
    while (i < v.length - 1 && v[i] === 0x00) {
      i++
    }
    let body = Array.from(v.slice(i))
    if (body[0] & 0x80) {
      body = [0x00, ...body] // DER sign byte
    }
    return [0x02, body.length, ...body]
  }
  const r = encodeInt(raw.slice(0, 32))
  const s = encodeInt(raw.slice(32))
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s])
}

async function makeSigned(body: string) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])
  const bytes = new TextEncoder().encode(body)
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, bytes),
  )
  const pem = spkiToPem(await crypto.subtle.exportKey('spki', kp.publicKey))
  return { bytes, rawSig, pem }
}

describe('verifyProofSignature', () => {
  it('verifies a DER-encoded signature over the exact bytes (the cryptod format)', async () => {
    const { bytes, rawSig, pem } = await makeSigned('{"proof":"canonical"}')
    const derB64 = bytesToB64(rawToDer(rawSig))
    expect(await verifyProofSignature(bytes, derB64, pem)).toBe(true)
  })

  it('verifies a raw r||s signature too (64-byte passthrough)', async () => {
    const { bytes, rawSig, pem } = await makeSigned('{"proof":"canonical"}')
    expect(await verifyProofSignature(bytes, bytesToB64(rawSig), pem)).toBe(true)
  })

  it('fails on a tampered body', async () => {
    const { rawSig, pem } = await makeSigned('{"proof":"canonical"}')
    const tampered = new TextEncoder().encode('{"proof":"TAMPERED"}')
    expect(await verifyProofSignature(tampered, bytesToB64(rawToDer(rawSig)), pem)).toBe(false)
  })

  it('fails on a tampered signature', async () => {
    const { bytes, rawSig, pem } = await makeSigned('{"proof":"canonical"}')
    const bad = new Uint8Array(rawSig)
    bad[10] ^= 0xff
    expect(await verifyProofSignature(bytes, bytesToB64(bad), pem)).toBe(false)
  })

  it('fails against the wrong key', async () => {
    const a = await makeSigned('{"proof":"canonical"}')
    const b = await makeSigned('{"proof":"canonical"}')
    expect(await verifyProofSignature(a.bytes, bytesToB64(rawToDer(a.rawSig)), b.pem)).toBe(false)
  })
})

describe('toRawSignature', () => {
  it('round-trips DER back to the original raw form', async () => {
    const { rawSig } = await makeSigned('x')
    expect(bytesToHex(toRawSignature(rawToDer(rawSig)))).toBe(bytesToHex(rawSig))
  })

  it('rejects garbage that is neither raw nor DER', () => {
    expect(() => toRawSignature(new Uint8Array([1, 2, 3]))).toThrow(/neither raw/)
  })
})

describe('helpers', () => {
  it('pemToDer rejects an empty body and decodes a real one', async () => {
    expect(() => pemToDer('-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----')).toThrow()
    const { pem } = await makeSigned('x')
    expect(pemToDer(pem).length).toBeGreaterThan(50)
  })

  it('sha256Hex matches a known vector', async () => {
    // SHA-256 of "abc"
    expect(await sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('b64ToBytes round-trips', () => {
    expect(bytesToHex(b64ToBytes('AAEC'))).toBe('000102')
  })
})

describe('toRawSignature edge vectors (fixed bytes, deterministic)', () => {
  // r = 31 bytes (short), s = 33 bytes with a DER sign byte: exercises left-padding and the
  // leading-zero strip deterministically (the random-key tests only hit these probabilistically).
  it('left-pads a short r and strips the sign byte of a padded s', () => {
    const r = new Uint8Array(31).fill(0x11)
    const sVal = new Uint8Array(32).fill(0xee) // high bit set, so DER prepends 0x00
    const der = new Uint8Array([
      0x30,
      2 + 31 + 2 + 33,
      0x02,
      31,
      ...r,
      0x02,
      33,
      0x00,
      ...sVal,
    ])
    const raw = toRawSignature(der)
    expect(raw.length).toBe(64)
    expect(raw[0]).toBe(0x00) // r left-padded
    expect(bytesToHex(raw.slice(1, 32))).toBe('11'.repeat(31))
    expect(bytesToHex(raw.slice(32))).toBe('ee'.repeat(32))
  })

  it('parses a long-form length header (0x81 xx)', () => {
    const r = new Uint8Array(32).fill(0x22)
    const s = new Uint8Array(32).fill(0x33)
    const der = new Uint8Array([0x30, 0x81, 68, 0x02, 32, ...r, 0x02, 32, ...s])
    const raw = toRawSignature(der)
    expect(bytesToHex(raw.slice(0, 32))).toBe('22'.repeat(32))
    expect(bytesToHex(raw.slice(32))).toBe('33'.repeat(32))
  })

  it('throws on a truncated DER body rather than fabricating a value', () => {
    // Declares a 32-byte r but provides 4 bytes total: the second INTEGER read must throw.
    const der = new Uint8Array([0x30, 68, 0x02, 32, 0xaa, 0xbb])
    expect(() => toRawSignature(der)).toThrow()
  })

  it('throws on an INTEGER wider than 32 bytes after zero-stripping', () => {
    const wide = new Uint8Array(35).fill(0x44)
    const der = new Uint8Array([0x30, 2 + 35 + 2 + 1, 0x02, 35, ...wide, 0x02, 1, 0x01])
    expect(() => toRawSignature(der)).toThrow(/wider/)
  })
})

describe('verifyInclusion (RFC 6962, browser side)', () => {
  const enc = (s: string) => new TextEncoder().encode(s)

  it('verifies a 2-leaf tree inclusion for both leaves', async () => {
    const la = await merkleLeafHash(enc('a'))
    const lb = await merkleLeafHash(enc('b'))
    const root = bytesToHex(await merkleNodeHash(la, lb))
    // leaf 0: sibling is Lb; leaf 1: sibling is La.
    expect(await verifyInclusion(bytesToHex(la), 0, 2, [bytesToHex(lb)], root)).toBe(true)
    expect(await verifyInclusion(bytesToHex(lb), 1, 2, [bytesToHex(la)], root)).toBe(true)
  })

  it('verifies an unbalanced 3-leaf tree (index 0 and 2)', async () => {
    const la = await merkleLeafHash(enc('a'))
    const lb = await merkleLeafHash(enc('b'))
    const lc = await merkleLeafHash(enc('c'))
    const nodeAB = await merkleNodeHash(la, lb)
    const root = bytesToHex(await merkleNodeHash(nodeAB, lc)) // n=3 splits at k=2
    // index 0: path leaf-to-root = [Lb, Lc]
    expect(
      await verifyInclusion(bytesToHex(la), 0, 3, [bytesToHex(lb), bytesToHex(lc)], root),
    ).toBe(true)
    // index 2: path = [nodeAB]
    expect(await verifyInclusion(bytesToHex(lc), 2, 3, [bytesToHex(nodeAB)], root)).toBe(true)
  })

  it('rejects a tampered leaf, wrong index, and out-of-range index', async () => {
    const la = await merkleLeafHash(enc('a'))
    const lb = await merkleLeafHash(enc('b'))
    const root = bytesToHex(await merkleNodeHash(la, lb))
    const wrong = bytesToHex(await merkleLeafHash(enc('x')))
    expect(await verifyInclusion(wrong, 0, 2, [bytesToHex(lb)], root)).toBe(false)
    expect(await verifyInclusion(bytesToHex(la), 1, 2, [bytesToHex(lb)], root)).toBe(false)
    expect(await verifyInclusion(bytesToHex(la), 2, 2, [bytesToHex(lb)], root)).toBe(false)
  })

  it('rejects non-32-byte leaf and path elements (splice-forgery regression)', async () => {
    // Without the width guard, leafHash = LH0 || LH1[:16] with path [LH1[16:]] reconstructs the
    // honest 2-leaf root from data that is not a leaf of the tree.
    const la = await merkleLeafHash(enc('a'))
    const lb = await merkleLeafHash(enc('b'))
    const root = bytesToHex(await merkleNodeHash(la, lb))
    const spliced = bytesToHex(la) + bytesToHex(lb).slice(0, 32) // 48 bytes as hex
    const tail = bytesToHex(lb).slice(32) // remaining 16 bytes as hex
    expect(await verifyInclusion(spliced, 0, 2, [tail], root)).toBe(false)
    // Empty leaf with the full concatenation as the single sibling.
    expect(await verifyInclusion('', 0, 2, [bytesToHex(la) + bytesToHex(lb)], root)).toBe(false)
    // Oversized path element on an otherwise honest proof.
    expect(await verifyInclusion(bytesToHex(la), 0, 2, [bytesToHex(lb) + '00'], root)).toBe(false)
  })

  it('throws loudly on malformed hex instead of coercing to zero bytes', async () => {
    const la = await merkleLeafHash(enc('a'))
    const lb = await merkleLeafHash(enc('b'))
    const root = bytesToHex(await merkleNodeHash(la, lb))
    const badHex = 'zz'.repeat(32) // right length, non-hex characters
    await expect(verifyInclusion(badHex, 0, 2, [bytesToHex(lb)], root)).rejects.toThrow(
      /malformed hex/,
    )
    await expect(verifyInclusion(bytesToHex(la), 0, 2, ['gg'.repeat(32)], root)).rejects.toThrow(
      /malformed hex/,
    )
  })
})
