# Spike 2 findings: C-SPANN vector index on the affordable tier

Status: NOT RUN YET

Run `run.py` against a local single-node cluster first, then a free Basic cloud cluster.

## Result

- [ ] PASS    (index builds + prefix-filtered search accelerates on a tier we can afford)
- [ ] PARTIAL (only Standard/Advanced/local, not free Basic -> budget/deploy change)
- [ ] FAIL    (cannot build anywhere, or prefix-filtered search does not accelerate)

## Record

| Check | Local single-node | Cloud Basic |
|-------|-------------------|-------------|
| `feature.vector_index.enabled` settable | | |
| `CREATE VECTOR INDEX (subject_id, embedding)` builds | | |
| prefix-filtered search index-accelerated (EXPLAIN) | | |
| prefix-filtered returns full k=5 | | |
| non-prefix filter returns full k | | |
| non-prefix filter accelerated or full scan | | |
| UPDATE indexed vector to NULL (erasure purge) works | | |

Paste both EXPLAIN plans here.

## Decisions this spike drives

- Tier: Basic ($0) if enabled works on Basic; else Standard on the $400 trial (activate Aug 16),
  else local demo cluster for the vector piece (README discloses the tier gate honestly).
- Erasure vector purge mechanism: `UPDATE ... SET embedding = NULL` if it survives the preview
  index; else `DELETE` the rows and copy ciphertext into a `shredded_memory` archive table inside
  the same transaction (framed as the backup that inevitably exists, retained for forensics).
- Filter design: if non-prefix filters do not return a full k, every filter we need becomes a
  prefix column (subject_id, crdb_region) or we over-fetch and post-filter in app code.

Honesty: C-SPANN is public preview and Euclidean-only at preview; design around `<->` (Euclidean).
