-- Named statements for the read-only forensics path (forensics_reader role, SELECT only).
-- These back the MCP server's verify_hash_chain, check_erasure_proof, and confirm_key_destroyed.

-- name: chain_walk
-- Walk the full decision log in order to recompute and verify the hash chain.
SELECT seq, subject_hash, action, lawful_basis, occurred_at, prev_hash, hash
FROM decision_log
ORDER BY seq;

-- name: erasure_lookup
-- The erasure record and its anchored proof reference for a subject.
SELECT subject_id, requested_at, committed_at, decision_log_seq, wrapped_key_fingerprint, proof_ref
FROM erasure_record
WHERE subject_id = $1;

-- name: key_absence
-- confirm_key_destroyed: the subject key row must be gone (0 = destroyed).
SELECT count(*) AS remaining
FROM subject_keys
WHERE subject_id = $1;

-- name: decision_for_subject
-- All decision-log rows for a subject hash (append-only history of decisions about them).
SELECT seq, action, lawful_basis, occurred_at, hash
FROM decision_log
WHERE subject_hash = $1
ORDER BY seq;
