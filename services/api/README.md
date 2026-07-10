# api (Go)

The orchestration layer and the erasure transaction, the core artifact of the project.

- Two pgx pools bound to distinct SQL roles (`agent_worker` for the write/search path, `operator`
  for erasure), least privilege inside one binary.
- The erasure runs in one `crdbpgx.ExecuteTx` closure: lock the subject key, read the decision-log
  chain head, append the hash-chained decision row, delete the wrapped key, NULL the live
  embedding, insert the erasure record. Pure DB and hashing only, no network call inside the
  closure, so a 40001 retry is always safe.
- SQL is loaded verbatim from `../../db/queries/*.sql` (no inlined SQL: the thin-swap seam).
- Post-commit, it calls `cryptod` to confirm key destruction, sign the proof, and anchor it.
