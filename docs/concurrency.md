# Concurrency: the gapless hash chain under contention

The decision log is append-only and hash-chained: each row's `seq` is `prev.seq + 1` and its `hash`
is `SHA-256(prev_hash || canonical_row)`, both assigned inside the one SERIALIZABLE erasure
transaction. This is a deliberate design: a single global, gapless sequence makes a dropped or
reordered entry detectable, which is the point of a tamper-evident log. It also makes the log a
serialization hot-spot, since every concurrent erasure competes for the same next `seq`.

This document reports what actually happens under that contention, measured, not asserted.

## What is measured

`TestErase_ConcurrentGaplessChainAtScale` (services/api/internal/erasure) seeds N subjects, fires N
erasures concurrently released by a single start barrier, then verifies the ENTIRE decision log is a
gapless, hash-intact chain: `seq` runs 1..N with no gaps, each `prev_hash` chains to the previous
row, and each `hash` equals the recomputed `chain.Link(...)`. It also checks every erasure committed
with a unique seq (no lost or duplicated appends), and logs per-erasure latency percentiles.

Under SERIALIZABLE, N transactions racing for the same next `seq` collide on the primary key; each
collision surfaces as a retryable `40001` (not a fatal duplicate-key error), which the official
`crdbpgx` wrapper retries. A gapless chain at the end is proof the serialization held: no two
erasures took the same seq, and none was lost.

## Measured results

Local, single-node CockroachDB `v25.2.20` (Docker, `--insecure`), operator pool sized to N+4 so the
erasures genuinely run at once rather than queueing on the pool:

| Concurrent erasures | Gapless chain 1..N | Wall clock | p50 | p95 | max | Notes |
|---|---|---|---|---|---|---|
| 25 (CI gate) | intact | ~0.4s | ~0.25s | ~0.4s | ~0.4s | reliable under `-race` on CI |
| 50 | intact | 1.05s | 0.57s | 0.91s | 1.05s | reliable locally |
| 100 | n/a | n/a | n/a | n/a | n/a | exceeded the retry budget, see below |

Every erasure at 25 and 50 committed with a unique seq and the whole chain verified gapless and
hash-intact. CI runs the N=25 case on every push (`go test -race`), so the invariant is checked
continuously, not just claimed.

## The honest limit

At 100 simultaneous single-node erasures, one transaction exhausted the `crdbpgx` default 50-retry
budget and returned a `40001` (`WriteTooOldError` on the `seq` key). This is not a bug; it is the
expected behavior of a single hot key under extreme contention. The global gapless sequence trades
write throughput for a strong, verifiable invariant, and that trade-off has a ceiling.

It is not a production scenario. Real erasure requests are spread over time (a person invokes their
right; a batch job runs on a schedule), not fired 100-at-once at a single node. Where higher erasure
throughput is genuinely needed, the sequence hot-spot is the thing to redesign (for example a
per-region or per-shard sub-sequence woven into a periodic Merkle checkpoint), which is why the
transparency log already signs Merkle roots. We report the ceiling rather than hide it: the claim is
"the gapless chain holds under concurrent erasure with no lost or duplicated appends," measured to
50-way concurrency, not "unlimited erasure throughput."

## Reproduce

```sh
# A local CockroachDB reachable at CRDB_DSN_TEST (the local rig or a single-node container).
CONCURRENCY_N=50 CRDB_DSN_TEST="postgresql://root@localhost:26257/erasure?sslmode=disable" \
  go test ./services/api/internal/erasure/ -run TestErase_ConcurrentGaplessChainAtScale -v
```
