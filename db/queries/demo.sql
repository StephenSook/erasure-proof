-- Named statements for the browser-facing demo gateway (read-only, plus the RBAC-denial probe).
-- These back the six-stage demo console; none of them expose plaintext or key material.

-- name: memory_preview
-- A non-sensitive preview of a subject's stored memory: byte lengths and whether the live plaintext
-- vector is still present (it is NULLed on erasure). Never returns the ciphertext bytes themselves.
SELECT id,
       length(content_ciphertext)   AS content_len,
       (embedding IS NOT NULL)       AS embedding_present,
       length(embedding_ciphertext)  AS embedding_len,
       created_at
FROM agent_memory
WHERE subject_id = $1;

-- name: subject_key_fingerprint
-- The retained SHA-256 fingerprint of a subject's wrapped key, if the key row still exists (it is
-- deleted on erasure). Absence is itself the crypto-shred evidence.
SELECT encode(wrapped_key_fingerprint, 'hex') AS fingerprint_hex
FROM subject_keys
WHERE subject_id = $1;

-- name: erasure_record_get
-- The recorded erasure-proof state for a subject, including the signed proof document served to
-- the browser-side WebCrypto verifier (proof_body is the exact signed bytes).
SELECT requested_at,
       committed_at,
       decision_log_seq,
       encode(wrapped_key_fingerprint, 'hex') AS fingerprint_hex,
       kms_key_arn,
       proof_ref,
       proof_body,
       proof_signature,
       signer_pubkey_pem
FROM erasure_record
WHERE subject_id = $1;

-- name: decision_log_all
-- The full hash-chained decision log, oldest first, for display and chain verification. subject_hash
-- is already pseudonymized (SHA-256), so this leaks no personal data.
SELECT seq,
       encode(subject_hash, 'hex') AS subject_hash_hex,
       action,
       lawful_basis,
       occurred_at,
       encode(prev_hash, 'hex') AS prev_hash_hex,
       encode(hash, 'hex')      AS hash_hex
FROM decision_log
ORDER BY seq;

-- name: decision_log_leaves
-- The decision-log row hashes in seq order, used as the leaves of the RFC 6962 Merkle transparency
-- tree. The leaf data is the row's chain hash, so the Merkle layer sits additively over the chain.
SELECT hash FROM decision_log ORDER BY seq;

-- name: decision_log_indexed
-- The leaves with their seq, so an inclusion proof can map a requested seq to its leaf index.
SELECT seq, hash FROM decision_log ORDER BY seq;

-- name: decision_log_verify
-- Raw bytes needed to recompute the hash chain in Go (chain.Link): the verifier walks these in seq
-- order and checks each stored hash against SHA-256(prev_hash || "seq|action|lawful_basis" || subject_hash).
SELECT seq, subject_hash, action, lawful_basis, hash
FROM decision_log
ORDER BY seq;

-- name: tt_insert
-- Time-travel beat: store a throwaway memory row for a fresh random subject (no subject key; the
-- row exists only to be deleted seconds later). Returns the generated ids.
INSERT INTO agent_memory (subject_id, content_ciphertext, embedding_ciphertext,
                          nonce_content, nonce_embedding, wrapped_key)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
RETURNING subject_id, id;

-- name: tt_delete
-- Time-travel beat: a NORMAL SQL DELETE of the throwaway row, the thing most systems call erasure.
DELETE FROM agent_memory WHERE id = $1;

-- name: tt_count
-- Time-travel beat: how many rows a normal read sees for the throwaway subject (0 after DELETE).
-- The AS OF SYSTEM TIME variant cannot be a named query: the clause requires a constant
-- expression, not a placeholder, so it is composed in Go against a strictly validated timestamp.
SELECT count(*) FROM agent_memory WHERE subject_id = $1;
