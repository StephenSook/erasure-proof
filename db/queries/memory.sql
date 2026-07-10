-- Named statements for the agent-memory write and retrieval path (agent_worker role).

-- name: insert_subject_key
-- Provision a subject: store the KMS-wrapped subject key exactly once. Run on the provisioning
-- (operator) path, not the agent, so the agent role never touches keys.
INSERT INTO subject_keys (subject_id, wrapped_key, kms_key_arn, key_origin, wrapped_key_fingerprint)
VALUES ($1, $2, $3, $4, $5);

-- name: insert_memory
-- Store an encrypted memory row: ciphertext content and embedding, the live plaintext vector for
-- C-SPANN search, nonces, and the per-row data key wrapped under the subject key.
INSERT INTO agent_memory (
    subject_id, content_ciphertext, embedding, embedding_ciphertext,
    nonce_content, nonce_embedding, wrapped_key, aad_context
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id;

-- name: subject_key_exists
-- Resurrection guard: the insert path checks the subject has not been erased. Read inside its own
-- SERIALIZABLE transaction so the read-write anti-dependency orders it safely against an erasure.
SELECT EXISTS (SELECT 1 FROM subject_keys WHERE subject_id = $1);

-- name: get_memory_ciphertext
-- Fetch the durable ciphertext for a subject (used by the forensics decrypt-attempt). aad_context
-- carries the exact AAD bytes the row was encrypted with (subject_id || chain head at write time).
-- MIGRATION NOTE for any decrypt consumer: rows written before the chain-binding change have
-- aad_context NULL; their actual AAD is the subject_id bytes alone (identical to the genesis
-- format). Treat NULL as that fallback or every legacy row will misread as undecryptable.
SELECT id, content_ciphertext, embedding_ciphertext, nonce_content, nonce_embedding, wrapped_key,
       aad_context
FROM agent_memory
WHERE subject_id = $1;

-- name: search_prefix
-- Prefix-filtered C-SPANN similarity search (Euclidean). subject_id is the index prefix, so this
-- is index-accelerated; the non-erased rows only (embedding IS NOT NULL after erasure sets it to
-- NULL). $2 is the query vector, $3 the k.
SELECT id, embedding <-> $2 AS distance
FROM agent_memory
WHERE subject_id = $1 AND embedding IS NOT NULL
ORDER BY embedding <-> $2
LIMIT $3;
