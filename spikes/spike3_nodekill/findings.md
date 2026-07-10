# Spike 3 findings: atomic erasure surviving a node kill

Status: PASS (run locally 2026-07-09)

Ran `./run.sh` (commit-then-kill variant) against the local 3-node cluster
(cockroachdb/cockroach:latest-v25.2) with the venv Python driver.

## Result

- [x] PASS: committed erasure state survived a node kill from a surviving replica, reproducibly
      across three runs; killed node restarted and rejoined.
- [ ] FAIL

## Record

| Field | Value |
|-------|-------|
| variant | commit-then-kill |
| runs survived | 3/3 |
| erase commit latency | 11.7ms, 23.6ms, 16.7ms (attempt 1 each, no 40001 retries needed) |
| decision_log seq incremented | 1, 2, 3 (gapless hash chain) |
| verify assertions | key_gone, log_present, record_present, embedding_null all True each run |
| killed node | roach2 (roach1/roach3 remain, Raft quorum preserved) |
| catch-up on restart | roach2 restarted and rejoined; explicit range-count catch-up not asserted by the script (add a `cockroach node status` check when scripting the recording) |
| CRDB image | cockroachdb/cockroach:latest-v25.2 |

## What this proves

The erasure transaction (append pseudonymized decision_log row, delete the wrapped-key row, NULL
the live embedding, insert erasure_record) commits atomically and the committed state survives
losing the node, from a surviving replica, via Raft. This is the resilience beat.

## Consequence

PASS -> proceed. The video's node-kill segment records against this local cluster (real Raft),
disclosed as local because the managed cloud cluster's nodes cannot be killed by us. Consider
scripting the harder mid-flight variant for extra drama, but the commit-then-kill result is fully
honest and sufficient.
