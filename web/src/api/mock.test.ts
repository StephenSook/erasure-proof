import { describe, expect, it } from 'vitest'
import { ApiError } from './types'
import { createMockClient } from './mock'

describe('mock client', () => {
  it('flips embedding_present and the key fingerprint on erasure', async () => {
    const api = createMockClient()
    const ing = await api.ingest('c', 'e')

    const before = await api.getMemory(ing.subject_id)
    expect(before.embedding_present).toBe(true)
    expect(before.key_fingerprint).not.toBe('')

    await api.erase(ing.subject_id)

    const after = await api.getMemory(ing.subject_id)
    expect(after.embedding_present).toBe(false)
    expect(after.key_fingerprint).toBe('')
  })

  it('has no proof before erasure', async () => {
    const api = createMockClient()
    await api.ingest('c', 'e')
    await expect(api.getProof('x')).rejects.toBeInstanceOf(ApiError)
  })

  it('reports the RBAC denial and an intact chain', async () => {
    const api = createMockClient()
    await api.ingest('c', 'e')
    await api.erase('x')

    const rbac = await api.rbacDemo()
    expect(rbac.denied).toBe(true)
    expect(rbac.sqlstate).toBe('42501')

    const chain = await api.verifyChain()
    expect(chain.intact).toBe(true)
    expect(chain.checked).toBe(2)
  })

  it('is isolated per instance', async () => {
    const a = createMockClient()
    const b = createMockClient()
    await a.ingest('c', 'e')
    // b never ingested, so it has no subject.
    await expect(b.getMemory('x')).rejects.toBeInstanceOf(ApiError)
  })

  it('reports live inversion unavailable and falls back honestly', async () => {
    const api = createMockClient()
    expect((await api.getInversionConfig()).live_available).toBe(false)
    // A 3072-byte embedding: the mock echoes the honest fallback shape with a real input hash.
    const emb = btoa(String.fromCharCode(...new Uint8Array(3072)))
    const live = await api.liveInversion(emb)
    expect(live.source).toBe('recorded_golden_run')
    expect(live.fell_back).toBe(true)
    expect(live.input_sha256).toMatch(/^[0-9a-f]{64}$/)
  })
})
