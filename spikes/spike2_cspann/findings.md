# Spike 2 findings: C-SPANN vector index on the affordable tier

Status: FULL PASS (local 2026-07-09, cloud Basic 2026-07-09). BRANCH A CONFIRMED: the free Basic
tier supports everything; database cost is $0 and the $400 trial stays in reserve.

Ran `run.py` against a local cluster (cockroachdb/cockroach:latest-v25.2) and against the free
CockroachDB Cloud Basic cluster `erasure-proof` (aws us-east-1, CockroachDB v25.4.10).

## Result

- [x] PASS on mechanics (index builds, prefix-filtered search accelerates, erasure purge works)
- [x] PASS on cloud Basic: `feature.vector_index.enabled` sets successfully on the free tier

## Record

| Check | Local single/3-node | Cloud Basic (free) |
|-------|---------------------|--------------------|
| `feature.vector_index.enabled` settable | yes | yes |
| `CREATE VECTOR INDEX (subject_id, embedding)` builds | yes | yes |
| prefix-filtered search index-accelerated (EXPLAIN) | yes (vector search on spike2_idx, prefix spans) | yes (same plan shape) |
| prefix-filtered returns full k=5 | yes (5/5) | yes (5/5) |
| non-prefix filter returns full k | yes (5/5 but...) | yes (5/5 but...) |
| non-prefix filter accelerated or full scan | FULL SCAN (not accelerated, as documented) | FULL SCAN (same) |
| UPDATE indexed vector to NULL (erasure purge) | yes (106 rows nulled, index survived) | yes (93 rows nulled, index survived) |

Prefix-filtered EXPLAIN (accelerated):

```
• vector search
  table: spike2_mem@spike2_idx
  target count: 5
  prefix spans: [/'<subject_id>' - /'<subject_id>']
```

Non-prefix filter EXPLAIN (full scan, confirms the documented limitation):

```
• top-k (k: 5)
  └── filter: embedding IS NOT NULL
      └── scan spike2_mem@spike2_mem_pkey  spans: FULL SCAN
```

## Decisions this spike drives

- Erasure vector purge mechanism: `UPDATE agent_memory SET embedding = NULL` works on a
  C-SPANN-indexed column and the index survives. Use it (no archive-table fallback needed locally).
- Filter design: non-prefix filters are NOT index-accelerated (confirmed FULL SCAN). Every filter
  we need must be a prefix column (subject_id is), or we over-fetch and post-filter in app code.
  Our query path filters on subject_id (the prefix), so we are accelerated.
- Tier: BRANCH A. The free Basic cluster (`erasure-proof`, aws us-east-1) carries the whole
  system of record including the C-SPANN vector path. No Standard cluster needed; the $400 trial
  stays in reserve as a contingency. Keepalive RU burn is noise against the 50M RU free credit.

Honesty: C-SPANN is public preview and Euclidean-only at preview; the demo uses `<->` (Euclidean).
