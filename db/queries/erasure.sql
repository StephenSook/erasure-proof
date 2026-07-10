-- Named statements for the erasure transaction and its post-commit anchoring.
-- Loaded verbatim by services/api (the thin-swap seam: no SQL is inlined in Go).
-- Format: each statement is preceded by `-- name: <name>`.
--
-- The steps between lock_subject_key and insert_erasure_record run inside ONE
-- crdbpgx.ExecuteTx closure (SERIALIZABLE, 40001-retried). No network call (KMS, S3, cryptod)
-- runs inside that closure, so a retry is always safe.

-- name: lock_subject_key
-- Lock the subject's key row and capture the fields the post-commit proof needs: the fingerprint,
-- the KMS key ARN, and the key origin (which decides whether a second KMS kill switch is invoked).
SELECT wrapped_key_fingerprint, kms_key_arn, key_origin
FROM subject_keys
WHERE subject_id = $1
FOR UPDATE;

-- name: chain_head
-- The current head of the hash-chained decision log (empty result = genesis).
SELECT seq, hash
FROM decision_log
ORDER BY seq DESC
LIMIT 1;

-- name: insert_decision
-- Append the pseudonymized, hash-chained decision-log row (subject_hash = SHA-256(subject_id)).
INSERT INTO decision_log (seq, subject_hash, action, lawful_basis, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: delete_subject_key
-- The crypto-shred: delete the only wrapped copy of the subject key.
DELETE FROM subject_keys
WHERE subject_id = $1;

-- name: null_embeddings
-- Purge the live plaintext vector; the durable ciphertext copy remains as provable noise.
UPDATE agent_memory
SET embedding = NULL
WHERE subject_id = $1;

-- name: insert_erasure_record
-- Record the erasure and tie it to the decision-log row that logged it. kms_key_arn is retained so
-- the reconciler can anchor the proof even though the subject_keys row is gone.
INSERT INTO erasure_record (subject_id, decision_log_seq, wrapped_key_fingerprint, kms_key_arn)
VALUES ($1, $2, $3, $4);

-- name: set_proof_ref
-- Post-commit: attach the anchored, signed proof URI once cryptod has signed and S3-anchored it.
UPDATE erasure_record
SET proof_ref = $2, committed_at = now()
WHERE subject_id = $1;

-- name: erasure_record_exists
-- Distinguish an already-erased subject from an unknown id when the key row is absent.
SELECT EXISTS (SELECT 1 FROM erasure_record WHERE subject_id = $1);

-- name: unanchored_erasures
-- Erasures whose proof was never anchored (a crash or a failed post-commit anchor). Joined to the
-- decision log to recover the subject_hash and chain head needed to rebuild the proof.
SELECT er.subject_id, er.decision_log_seq, er.wrapped_key_fingerprint, er.kms_key_arn,
       dl.subject_hash, dl.hash
FROM erasure_record er
JOIN decision_log dl ON dl.seq = er.decision_log_seq
WHERE er.proof_ref IS NULL;
