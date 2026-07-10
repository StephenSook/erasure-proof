-- 0003_vector_index.sql
-- CockroachDB C-SPANN distributed vector index (public preview since v25.2).
--
-- Spike 2 verifies whether feature.vector_index.enabled can be set on the affordable tier
-- (Basic availability is UNVERIFIED; it works on a local/self-hosted cluster). If Basic gates
-- the setting, the vector path moves to a Standard cluster ($400 trial) or a local demo cluster.
--
-- The index is prefixed on subject_id (high cardinality). C-SPANN keeps a separate K-means tree
-- per prefix value, and index acceleration with filters is only supported when the filter matches
-- a prefix column (issue #146145). subject_id is the filter we actually need, so it is the prefix.
-- C-SPANN is Euclidean-only at preview; the demo is designed around Euclidean distance (<->).

SET CLUSTER SETTING feature.vector_index.enabled = true;

-- On a non-empty table, sql_safe_updates must be off to add the index.
SET sql_safe_updates = false;

CREATE VECTOR INDEX IF NOT EXISTS mem_idx ON agent_memory (subject_id, embedding);

SET sql_safe_updates = true;
