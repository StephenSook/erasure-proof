# tests

The four judged guarantees are exercised as close to production as possible, so their tests live
with the code they cover rather than in one directory here:

- Append-only rejection: the `db-smoke` CI job connects as the real `agent_worker` role and asserts
  INSERT succeeds while UPDATE and DELETE are denied (`.github/workflows/ci.yml`,
  `db/migrations/0002_roles.sql`).
- Atomicity, both-or-neither under an injected 40001: `services/api/internal/erasure/erasure_test.go`
  (`TestErase_SurvivesInjectedRetries`), run against a real CockroachDB in the `go-api` job.
- Full write -> erase -> InvalidTag -> proof loop: the zero-mock `e2e-realstack` browser test
  (`web/e2e/realstack.spec.ts`) plus the cryptod crypto tests (`services/cryptod/tests`).
- Node-kill durability (Raft): `spikes/spike3_nodekill/` on the local 3-node cluster (`make spike3`).

Per-service unit tests live next to their code (for example `services/cryptod/tests`).
