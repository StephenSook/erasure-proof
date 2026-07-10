# db

CockroachDB schema and queries. Plain SQL, run by golang-migrate (no ORM).

- `migrations/`: ordered, additive schema (applied by glob `0*.sql`):
  - `0001_schema.sql`: the four tables (agent_memory, subject_keys, decision_log, erasure_record).
  - `0002_roles.sql`: least-privilege roles; append-only decision log via REVOKE UPDATE, DELETE.
  - `0003_vector_index.sql`: the C-SPANN vector index, prefixed on subject_id.
  - `0004_rls.sql`: row-level security; the agent role is scoped to its declared subject, fail-closed.
  - `0005_proof_document.sql`: the signed proof body/signature/key stored on erasure_record.
- `migrations/optional/`: prepared but NOT applied by default:
  - `0006_regional_by_row.sql`: geo-domiciling. agent_memory + subject_keys become REGIONAL BY ROW
    (a subject's encrypted memory and wrapped key pin to a region), decision_log + erasure_record
    become GLOBAL (pseudonymized compliance artifacts, read everywhere). Requires a cluster with
    region localities; the judge-facing Basic tier is single-region, so this is verified locally
    by `deploy/local/rbr-verify.sh` (3-region docker cluster; proves the conversion, per-row
    domiciling, RLS survival, and that C-SPANN search still answers) and deliberately not enabled
    in the deployed demo. We do not claim multi-region operation anywhere judge-facing.
- `queries/`: named SQL statements loaded verbatim by the Go API (the thin-swap seam):
  `erasure.sql`, `memory.sql`, `forensics.sql`.
- `seed/`: the real-data memory corpus loader.
