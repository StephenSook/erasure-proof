-- 0001_schema.sql
-- Four tables. The whole project's data model.
--
-- Design notes (all defended in ARCHITECTURE.md and SECURITY.md):
--  * agent_memory carries BOTH a nullable plaintext `embedding VECTOR(768)` (live-serving
--    state that C-SPANN can index and search) AND `embedding_ciphertext` (the durable
--    AES-256-GCM copy). C-SPANN cannot search ciphertext; that is CyborgDB's product, which
--    we cite. The honest threat model: every DURABLE copy (backups, MVCC history, replica
--    disks, exports) only ever contains ciphertext. The plaintext vector is live-serving state
--    that the erasure transaction sets to NULL and which then ages out of the GC window
--    (CockroachDB Basic fixes gc.ttlseconds at 4500s / 1h15m; stated on the demo page).
--  * A single explicit column family avoids the C-SPANN preview bug where vector queries can
--    return incorrect results on multi-column-family tables (cockroachdb issue #146046).
--  * LOCALITY REGIONAL BY ROW is applied later in 0006 (multi-region only); the base table is
--    single-region so it runs on a local cluster and on the free Basic tier.

CREATE TABLE IF NOT EXISTS agent_memory (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id            UUID NOT NULL,
    content_ciphertext    BYTES NOT NULL,        -- AES-256-GCM
    embedding             VECTOR(768),           -- nullable live plaintext; erasure sets NULL
    embedding_ciphertext  BYTES NOT NULL,        -- AES-256-GCM durable copy
    nonce_content         BYTES NOT NULL,        -- 96-bit, fresh per row
    nonce_embedding       BYTES NOT NULL,        -- 96-bit, fresh per row
    wrapped_key           BYTES NOT NULL,        -- per-row data key, wrapped under the subject key
    aad_context           BYTES,                 -- should-build: subject_id || decision_log chain head
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    FAMILY f_all (id, subject_id, content_ciphertext, embedding, embedding_ciphertext,
                  nonce_content, nonce_embedding, wrapped_key, aad_context, created_at)
);

CREATE INDEX IF NOT EXISTS agent_memory_by_subject ON agent_memory (subject_id);

-- subject_keys holds the KMS-wrapped per-subject key EXACTLY ONCE. Erasure deletes this row,
-- rendering every per-row `wrapped_key` permanently unwrappable while ciphertext survives as
-- provable noise. wrapped_key_fingerprint is a SHA-256 that is safe to retain in proofs.
CREATE TABLE IF NOT EXISTS subject_keys (
    subject_id               UUID PRIMARY KEY,
    wrapped_key              BYTES NOT NULL,
    kms_key_arn              STRING NOT NULL,
    key_origin               STRING NOT NULL,   -- 'GENERATE_DATA_KEY' | 'IMPORTED_MATERIAL'
    wrapped_key_fingerprint  BYTES NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- decision_log is the append-only, hash-chained record retained for compliance
-- (EU AI Act Article 19(1) / MiFID II) even after the personal data is erased.
-- seq is assigned as prev.seq + 1 inside the SERIALIZABLE erasure transaction; concurrent
-- appends conflict and retry (40001), which is exactly how a gapless chain stays correct.
CREATE TABLE IF NOT EXISTS decision_log (
    seq           INT8 NOT NULL,
    subject_hash  BYTES NOT NULL,          -- SHA-256(subject_id); pseudonymized, never raw PII
    action        STRING NOT NULL,         -- e.g. 'erasure', 'ingest'
    lawful_basis  STRING NOT NULL,         -- e.g. 'gdpr_art_17', 'ai_act_art_19'
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash     BYTES NOT NULL,          -- hash of the previous row (genesis = 32 zero bytes)
    hash          BYTES NOT NULL,          -- SHA-256(prev_hash || canonical_row_bytes)
    PRIMARY KEY (seq)
);

CREATE INDEX IF NOT EXISTS decision_log_by_subject ON decision_log (subject_hash);

-- erasure_record ties a subject's erasure to its externally anchored, ECDSA-signed proof.
CREATE TABLE IF NOT EXISTS erasure_record (
    subject_id               UUID PRIMARY KEY,
    requested_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    committed_at             TIMESTAMPTZ,
    decision_log_seq         INT8,                 -- the decision_log row that recorded this erasure
    wrapped_key_fingerprint  BYTES,                -- retained proof that a key once existed
    proof_ref                STRING                -- s3://... URI of the signed proof (set post-commit)
);
