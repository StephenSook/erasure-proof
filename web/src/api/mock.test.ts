import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes, merkleLeafHash, verifyConsistency, verifyInclusion } from '../verify'
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

  it('erasure stream sends a snapshot then pushes the erasure row live', async () => {
    const api = createMockClient()
    await api.ingest('c', 'e')
    let snapshotLive: boolean | null = null
    const rows: number[] = []
    const unsub = api.subscribeErasureStream({
      onSnapshot: (r, live) => {
        snapshotLive = live
        r.forEach((row) => rows.push(row.seq))
      },
      onRow: (row) => rows.push(row.seq),
    })
    // Snapshot fired synchronously with the current log (seq 1) and live=false (no changefeed).
    expect(snapshotLive).toBe(false)
    expect(rows).toEqual([1])
    // Erasing pushes the new row (seq 2) to the subscriber.
    await api.erase('x')
    expect(rows).toEqual([1, 2])
    unsub()
    // After unsubscribe, no more rows arrive.
    await createMockClient() // fresh instance to avoid touching this one's erased state
    expect(rows).toEqual([1, 2])
  })

  it('proof carries Merkle fields that verify inclusion + consistency in the browser', async () => {
    // Mirrors the /proof/:id transparency panel: recompute the leaf from the SIGNED head, prove
    // inclusion in the signed tree, and prove the current log is an append-only extension.
    const api = createMockClient()
    await api.ingest('c', 'e')
    await api.erase('x')
    const proof = await api.getProof('any')
    const body = JSON.parse(proof.proof_body ?? '{}') as Record<string, unknown>
    const head = String(body.decision_log_head)
    const signedRoot = String(body.merkle_root)
    const signedSize = Number(body.tree_size)
    const seq = Number(body.decision_log_seq)

    const inc = await api.getInclusion(seq, signedSize)
    const leafHashHex = bytesToHex(await merkleLeafHash(hexToBytes(head)))
    expect(await verifyInclusion(leafHashHex, inc.leaf_index, signedSize, inc.audit_path, signedRoot)).toBe(
      true,
    )

    const th = await api.getTreeHead()
    const cons = await api.getConsistency(signedSize, th.tree_size)
    expect(await verifyConsistency(signedSize, th.tree_size, cons.proof, signedRoot, cons.root_to)).toBe(
      true,
    )
  })

  it('memory-writer distils a fact, stores a subject, labeled recorded', async () => {
    const api = createMockClient()
    expect((await api.getAgentConfig()).memory_writer_available).toBe(false)
    const written = await api.writeMemory("Hi, I'm Marie Curie. I discovered radium.")
    expect(written.source).toBe('recorded')
    expect(written.memory_text).toBe("Hi, I'm Marie Curie.")
    expect(written.subject_id).toMatch(/^[0-9a-f-]{36}$/)
    // The written memory becomes the live subject the loop reads.
    const mem = await api.getMemory(written.subject_id)
    expect(mem.subject_id).toBe(written.subject_id)
    expect(mem.embedding_present).toBe(true)
  })

  it('forensics agent verdict reflects real erasure state, labeled as recorded', async () => {
    const api = createMockClient()
    expect((await api.getAgentConfig()).live_available).toBe(false)
    await api.ingest('c', 'e')

    // Before erasure: NOT PROVEN, and the tool trace shows the key row still present.
    const before = await api.forensicsAudit('any')
    expect(before.source).toBe('recorded')
    expect(before.verdict).toMatch(/NOT PROVEN/)
    expect(before.tool_calls?.[0].output.destroyed).toBe(false)

    // After erasure: PROVEN, trace shows destroyed + erasure recorded.
    await api.erase('x')
    const after = await api.forensicsAudit('any')
    expect(after.verdict).toMatch(/PROVEN/)
    expect(after.tool_calls?.[0].output.destroyed).toBe(true)
  })
})
