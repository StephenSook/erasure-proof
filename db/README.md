# db

CockroachDB schema and queries. Plain SQL, run by golang-migrate (no ORM).

- `migrations/`: ordered, additive schema:
  - `0001_schema.sql`: the four tables (agent_memory, subject_keys, decision_log, erasure_record).
  - `0002_roles.sql`: least-privilege roles; append-only decision log via REVOKE UPDATE, DELETE.
  - `0003_vector_index.sql`: the C-SPANN vector index, prefixed on subject_id.
  - later: `0004` associated-data binding, `0005` RLS, `0006` REGIONAL BY ROW (should-build).
- `queries/`: named SQL statements loaded verbatim by the Go API (the thin-swap seam):
  `erasure.sql`, `memory.sql`, `forensics.sql`.
- `seed/`: the real-data memory corpus loader.
