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

-- name: search_prefix
-- Prefix-filtered C-SPANN similarity search (Euclidean). subject_id is the index prefix, so this
-- is index-accelerated. $2 is the query vector, $3 the k.
--
-- Deliberately NO "embedding IS NOT NULL" filter: verified empirically on v25.2.20 that (a) any
-- non-prefix filter disqualifies C-SPANN acceleration (the planner falls back to a plain
-- subject-id index plus top-k, consistent with issue #146145: only prefix-column filters are
-- supported), and (b) the filter is redundant anyway, because rows whose vector was destroyed by
-- erasure (embedding = NULL) never surface from the vector search operator. Same result set, and
-- EXPLAIN shows "vector search table: agent_memory@mem_idx".
SELECT id, embedding <-> $2 AS distance
FROM agent_memory
WHERE subject_id = $1
ORDER BY embedding <-> $2
LIMIT $3;
