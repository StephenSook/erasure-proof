# Architecture

## Components

- `services/api` (Go): the orchestration layer and the erasure transaction. pgx v5 with the
  official `github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgx` retry wrapper. Two connection
  pools bound to distinct SQL roles (`agent_worker` for the write/search path, `operator` for
  erasure). SQL lives in `db/queries/*.sql`, loaded verbatim (no inline SQL), so the thin layer
  can swap to TypeScript if needed.
- `services/cryptod` (Python): all key handling. AES-256-GCM (pyca/cryptography), the two-level
  envelope hierarchy, KMS (GenerateDataKey and the imported-material DeleteImportedKeyMaterial
  kill switch), ECDSA P-256 proof signing, S3 Object Lock anchoring, GTR-base embedding, and
  Vec2Text inversion. Python is mandatory because Vec2Text ships only as PyTorch models.
- `services/mcpserver` (Python): a genuinely read-only forensics MCP server (official MCP Python
  SDK, pinned `mcp>=1.27,<2`) exposing exactly four tools, each audit-logged, over a SELECT-only
  role.
- `services/agents` (Python): a memory-writer agent (real Bedrock inference feeding the memory
  layer) and a forensics agent (a Bedrock Claude tool-use loop bridged to the MCP client).
- `web` (React + Vite): the landing page, the live demo console, the public proof verifier, and
  the `/trust` honesty page.
- CockroachDB: the system of record. Local 3-node cluster for the node-kill laboratory; a managed
  CockroachDB Cloud cluster behind the deployed app.

## Data model

Four tables (`db/migrations/0001_schema.sql`): `agent_memory`, `subject_keys`, `decision_log`,
`erasure_record`.

Two design resolutions the concept's DDL required:

1. `agent_memory` carries both a nullable plaintext `embedding VECTOR(768)` (live-serving state
   that C-SPANN can index and search) and `embedding_ciphertext` (the durable AES-256-GCM copy).
   C-SPANN cannot search ciphertext; that is CyborgDB's product, which we cite. The honest threat
   model: every durable copy (backups, MVCC history, replica disks, exports) only ever contains
   ciphertext. The plaintext vector is live-serving state that the erasure transaction sets to
   NULL, and it then ages out of the GC window (CockroachDB Basic fixes gc.ttlseconds at 4500s /
   1h15m; this bound is stated on the demo page).
2. `subject_keys` holds the KMS-wrapped per-subject key exactly once. Each `agent_memory.wrapped_key`
   is a per-row data key wrapped under the subject key (a two-level envelope hierarchy). Erasure is
   `DELETE FROM subject_keys WHERE subject_id = $1`: every per-row key becomes permanently
   unwrappable while ciphertext survives as provable noise (the demo requires ciphertext to survive
   erasure so inversion of the surviving bytes returns noise).

## The erasure transaction (the core artifact)

One `crdbpgx.ExecuteTx` closure, pure DB plus hashing, no network call inside it so a 40001 retry
is always safe:

1. `SELECT wrapped_key_fingerprint FROM subject_keys WHERE subject_id = $1 FOR UPDATE`.
2. Read the decision-log chain head (`MAX(seq)`, its `hash`).
3. `INSERT INTO decision_log` a pseudonymized, hash-chained row
   (`hash = SHA-256(prev_hash || canonical_row_bytes)`, `seq = prev + 1`).
4. `DELETE FROM subject_keys WHERE subject_id = $1` (the crypto-shred).
5. `UPDATE agent_memory SET embedding = NULL WHERE subject_id = $1` (purge the live plaintext).
6. `INSERT INTO erasure_record`.
7. COMMIT.

Post-commit, outside the transaction: `cryptod` confirms key destruction (and calls KMS
`DeleteImportedKeyMaterial` for imported-material subjects), signs the proof, and anchors the
digest in S3 Object Lock. An `anchor-reconciler` sweeps `erasure_record WHERE proof_ref IS NULL`
to cover a crash between commit and anchor.

The memory-insert path guards against post-erasure resurrection by reading the `subject_keys` row
inside its own serializable transaction; the read-write anti-dependency makes the race safe.

## Crypto-erasure pattern

Per-subject envelope encryption. We do NOT use KMS ScheduleKeyDeletion (7-30 day floor, cannot
complete in a demo). Standard subjects: one wrapping CMK, `GenerateDataKey(AES_256,
EncryptionContext={subject_id})`, erase by deleting the wrapped-key row. High-assurance subjects
(the demo subject): a per-subject external-material CMK so erasure also calls
`DeleteImportedKeyMaterial` (immediate, subject to eventual consistency). Maps to NIST SP 800-88
Rev. 2 cryptographic erase (a Purge technique). Every ciphertext binds `subject_id` (and,
should-build, the decision-log chain head) as AES-GCM associated data, so a ciphertext cannot be
replayed under another subject or against a rewritten log without failing with `InvalidTag`.

## Local cluster vs CockroachDB Cloud

The local 3-node cluster (`docker-compose.crdb.yml`) is the failure-domain laboratory: the
node-kill beat, `inject_retry_errors_enabled` tests, tier-gate-free C-SPANN, and CI durability
tests. The managed cloud cluster is the judge-facing system of record and the only home of the
Managed MCP Server, the ccloud RBAC boundary, and the funded-warm cluster through judging. We
never kill the cloud cluster's nodes and never point destructive tests at it.
