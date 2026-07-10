# erasure-proof

Provable, durable, statute-compliant erasure for AI agent memory, on CockroachDB and AWS.

When a regulator asks whether a person's data is truly gone from an AI agent's memory, most
systems can only prove they deleted a row. Deleting the row is not enough: the embedding is still
reconstructible. Text-embedding inversion (Vec2Text, Morris et al., arXiv:2310.06816) recovers
names from the vector alone. This project crypto-shreds the embedding by destroying its key,
atomically retains the legally required decision log in one serializable transaction, emits an
ECDSA-signed proof anchored in write-once storage, and proves the erasure survives a node failure.

This is incident response and compliance for agent memory. It is not detection.

> Status: in active development for the CockroachDB x AWS "Build with Agentic Memory" hackathon
> (submission deadline Aug 18, 2026). Component readiness is tracked honestly in the
> [Capability tiers](#capability-tiers) table below and on the app's `/trust` page. Nothing is
> claimed as live until it ships and is verifiable in this repo.

## The one closeable loop

An erasure request arrives -> the system cryptographically destroys the personal embedding so it
cannot be reconstructed -> it atomically retains the pseudonymized decision log the law requires
-> it emits an externally anchored, signed proof -> the erasure holds durably across a node kill.

## Capability tiers (honesty moat)

Every claim in this project is labeled by how far it is actually built. This table is the source
of truth and is mirrored on the app `/trust` page.

| Capability | Tier | Notes |
|-----------|------|-------|
| Schema, least-privilege roles, append-only decision log | in progress | migrations 0001-0002 |
| C-SPANN vector index on the affordable tier | spike pending | gated by spike 2 |
| Vec2Text name-then-noise leak/erasure beat | spike pending | gated by spike 1 (Colab GPU) |
| Atomic erasure surviving a node kill | spike pending | gated by spike 3 (local 3-node) |
| AES-256-GCM envelope crypto + KMS key destruction | planned | Phase 2 |
| ECDSA-signed proof + S3 Object Lock anchor | planned | Phase 2 |
| Read-only forensics MCP server | planned | Phase 2 |
| Deployed live demo app | planned | Phase 3 |

Tiers used: `wired-live` (runs live in the deployed app), `integration` (built and tested, not yet
on the live path), `spike pending` / `in progress` / `planned` (not yet built). No capability is
described in the pitch at a higher tier than it holds here.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component contract and data flow,
[SECURITY.md](SECURITY.md) for the threat model and the exact honest conditions on every claim,
and [COMPLIANCE.md](COMPLIANCE.md) for the GDPR Article 17 vs EU AI Act Article 19 reconciliation.

- Go API + erasure orchestrator (pgx + the official `cockroach-go/crdb` 40001 retry wrapper).
- Python microservice for all crypto, KMS, Vec2Text, and the read-only forensics MCP server.
- CockroachDB: serializable transactions, C-SPANN vector index, row-level security, the system of
  record for agent memory.
- AWS: KMS (the erasure mechanism), S3 Object Lock (the proof anchor), Bedrock (agent inference),
  ECS/Fargate (the always-on erasure path).

## CockroachDB tools used

(Filled in as each is wired; the hackathon requires at least two. Target: all four.)

- Distributed Vector Indexing (C-SPANN): the agent's embeddings, prefixed on subject_id.
- Managed MCP Server: forensic verification reads via `select_query`.
- ccloud CLI (service-account RBAC): least-privilege control-plane access, the 403 boundary.
- Agent Skills: consumed, plus an upstream contribution (a verify-erasure-proof skill).

## AWS services used

(Filled in as each is wired; the hackathon requires at least one.)

- AWS KMS: envelope encryption; destroying the key is the actual erasure.
- Amazon S3 Object Lock (COMPLIANCE): the immutable, externally anchored proof.
- Amazon Bedrock (Claude): agent inference; optional Titan v2 for an AWS-native embedding shown in
  parallel.
- Amazon ECS / Fargate: the always-on, connection-pooled erasure path.

---

The following sections map to the five equally weighted judging criteria.

## Agentic Memory Design

CockroachDB is the system of record for the full memory lifecycle: write, retrieve, erase, prove.
The `agent_memory` row stores the embedding only as ciphertext for durability, plus a live
plaintext vector that C-SPANN indexes for search; per-subject envelope keys make each subject's
memory independently destroyable; the hash-chained `decision_log` is itself retained agent memory.
(Details: [ARCHITECTURE.md](ARCHITECTURE.md).)

## Technical Implementation

The destroy-and-retain erasure runs in one serializable transaction with the official 40001 retry
wrapper; AES-256-GCM binds subject_id as associated data; the erasure emits an ECDSA P-256 proof;
a genuinely read-only MCP server exposes four forensic tools; a hypothesis property-test suite
proves the invariant. (Details: [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md).)

## Real-World Impact

GDPR Article 17 compels erasure; EU AI Act Article 19(1) (effective Aug 2, 2026) compels retaining
auto-generated logs; MiFID II sets a longer floor for financial entities. These obligations point
in opposite directions and no single system reconciles them today. (Details:
[COMPLIANCE.md](COMPLIANCE.md).)

## Production Readiness

CI runs lint, typecheck, and tests on every push; the erasure path runs on always-on Fargate with
a warm pool; three separated IAM principals with confused-deputy conditions; circuit-breaker
deploys; a recorded node-kill durability proof; a keepalive watchdog through judging; a `/trust`
honesty page. (Details: [SECURITY.md](SECURITY.md).)

## Creativity & Originality

The primitive (crypto-shredding) is standard (NIST SP 800-88 Rev. 2) and CyborgDB ships the
encrypted-vector version. The contribution is the combination: a crypto-erased embedding, an
atomically retained decision log, and an externally anchored signed proof, on a database that
survives node loss, reconciling GDPR Article 17 against EU AI Act Article 19. Prior art (CyborgDB,
MemLineage, OWASP Agent Memory Guard, Zep) is cited proactively in [SECURITY.md](SECURITY.md).

## Setup and run

Local quickstart (filled out as the stack lands):

```bash
cp .env.example .env            # fill in placeholders
make cluster-up                 # local 3-node CockroachDB + HAProxy (needs Docker)
make migrate                    # apply db/migrations
make spike3                     # atomic-erasure-survives-node-kill demo
```

The three week-one spikes live in `spikes/` and gate the build; see each `findings.md`.

## License

[Apache-2.0](LICENSE).
