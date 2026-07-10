# Security and honest-claim conditions

The judges are distributed-systems and governance engineers. Every claim here is one we can
defend, and every limitation is stated proactively.

## The honest conditions on every claim

- Crypto-erasure is irreversible only if the plaintext data key was never persisted and no wrapped
  key or key material was backed up, escrowed, or stored externally (NIST SP 800-88 Rev. 2, the
  forward-secrecy condition). We destroy the only wrapped copy inside the transaction and, for
  imported-material subjects, delete the key material in KMS. Vectors an attacker exfiltrated
  before erasure remain compromised; crypto-erasure protects the stored copy, not prior copies.
- The append-only decision log holds against the `agent_worker` and `operator` roles (they lack
  UPDATE and DELETE). It does NOT hold against the owner/admin, because CockroachDB privileges
  derive from ownership. The property is only as strong as custody of the `crdb_admin_owner`
  credential. We never claim the table is immutable to everyone.
- CockroachDB is serializable and single-key linearizable, NOT strictly serializable (Jepsen). We
  say "serializable".
- C-SPANN is in public preview and Euclidean-only at preview. We design around Euclidean distance
  and disclose the preview status.
- Row-Level Security is incompatible with change-data-capture queries on the same table, and
  changefeeds do not filter by RLS. We run changefeeds on non-RLS audit tables.
- Tamper-evidence is app-side hash chaining plus S3 Object Lock. CockroachDB has no native
  cryptographic ledger; we never imply DB-enforced tamper-evidence.

## Threat model

- The plaintext embedding is live-serving state only. Durable copies (backups, MVCC history,
  replica disks, exports) contain only ciphertext. Erasure NULLs the live vector and destroys the
  key, so both the ciphertext-at-rest and the MVCC history become unreadable.
- Every ciphertext is bound to its audit context via AES-GCM associated data: AAD =
  `subject_id || decision-log chain head at write time`, with the exact bytes retained in
  `agent_memory.aad_context`. Decryption requires presenting that binding, so a ciphertext cannot
  be silently re-attributed to a different subject or divorced from the log state it was written
  under. The binding is to the head at encryption time (later log growth does not invalidate it).
  Precise scope: an AAD reconstructed from a tampered history fails InvalidTag; storing the exact
  bytes makes the binding verifiable against the log, it does not make decryption depend on the
  log's current state. The AAD proves the writer observed that head, not that it was still the
  head at commit.
- The agent role cannot read or destroy keys (no grants on `subject_keys`) and cannot rewrite the
  decision log. The operator role can erase but cannot rewrite history. The forensics role is
  SELECT-only.
- Row-level security scopes the agent role to ONE subject per session (`SET app.subject_id`,
  fail-closed when unset: an undeclared session sees no rows and cross-subject writes are denied).
  Honest scope: RLS binds the agent to the subject its session DECLARES; the application layer
  chooses that value, so this contains cross-subject blast radius rather than authenticating
  subjects. The owner/admin bypass and the RLS-vs-CDC incompatibility above apply.
- AWS: three separated principals (KMS/erasure, S3-write, Bedrock) with `aws:SourceArn` /
  `aws:SourceAccount` confused-deputy conditions, and a KMS key policy that requires the
  `subject_id` encryption context so a call without it is denied. No single principal holds both
  the KMS-destroy and the S3-write permission.

## Prior art (cited proactively, not hidden)

- CyborgDB: ships the encrypted-vector erasure primitive (destroy the keys, data becomes
  cryptographic noise). It does not do retained-decision-log reconciliation, single-transaction
  atomicity of destroy-plus-retain, or a signed proof of erasure.
- MemLineage (arXiv:2605.14421) and OWASP Agent Memory Guard: memory provenance and quarantine
  already exist; we do not claim to have invented them (that is the fallback concept, not this
  one).
- Zep: the closest compliance-adjacent memory product; it is a temporal knowledge graph, not a
  unified transactional relational+vector+audit store.

Our novelty is the combination only: crypto-erased embedding + atomically retained decision log +
externally anchored signed proof + Article 17 vs Article 19 reconciliation, on a database that
survives node loss.

## Never claimed (permanently struck)

Fabricated or falsified during research; never write these anywhere:

- "PostgreSQL saturates at 1,000 agents while CockroachDB holds to 50,000." The real figure is a
  ~2.3x advantage at 5,000 agents with the vendor's "test your own workload" caveat.
- Any specific Request Unit cost; only documented ranges exist.
- Any native CockroachDB cryptographic ledger, or separate billing for follower reads.
- That filtered vector search returns a full k after a non-prefix filter (undocumented; proven or
  worked around in spike 2).
- AWS QLDB (deprecated 2025-07-31). Strict serializability. Any CVE attached to Cisco MemoryTrap
  (it has none; patched in Claude Code v2.1.50).

## Reporting

This is a hackathon project, not production software. Do not store real third-party personal data
in it. The demo uses the author's own self-consented data.
