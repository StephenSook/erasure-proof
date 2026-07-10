# Spike 2 findings: C-SPANN vector index on the affordable tier

Status: PASS on the mechanics (local, 2026-07-09). Cloud Basic-tier availability still OPEN.

Ran `run.py` against a local cluster (cockroachdb/cockroach:latest-v25.2). The remaining question
is whether `feature.vector_index.enabled` can be set on the free CockroachDB Cloud Basic tier,
which needs a cloud cluster to answer (a budget/deploy question, not a concept question).

## Result

- [x] PASS on mechanics (index builds, prefix-filtered search accelerates, erasure purge works)
- [ ] Cloud Basic tier availability: NOT YET TESTED (needs a cloud cluster)

## Record

| Check | Local single/3-node | Cloud Basic |
|-------|---------------------|-------------|
| `feature.vector_index.enabled` settable | yes | untested |
| `CREATE VECTOR INDEX (subject_id, embedding)` builds | yes | untested |
| prefix-filtered search index-accelerated (EXPLAIN) | yes (vector search on spike2_idx, prefix spans) | untested |
| prefix-filtered returns full k=5 | yes (5/5) | untested |
| non-prefix filter returns full k | yes (5/5 but...) | untested |
| non-prefix filter accelerated or full scan | FULL SCAN (not accelerated, as documented) | untested |
| UPDATE indexed vector to NULL (erasure purge) | yes (106 rows nulled, index survived) | untested |

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
- Tier: mechanics work locally. Still to confirm on cloud Basic; if Basic gates the cluster
  setting, use Standard on the $400 trial (activate Aug 16) or demo the vector piece on a local
  cluster and disclose the tier gate honestly. This is Branch A/B/C, a budget decision.

Honesty: C-SPANN is public preview and Euclidean-only at preview; the demo uses `<->` (Euclidean).
