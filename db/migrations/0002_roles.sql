-- 0002_roles.sql
-- Least-privilege SQL roles. The agent never owns the audit tables.
--
-- Honest boundary (stated in SECURITY.md and on the /trust page): append-only holds against
-- agent_worker and operator, NOT against the owner/admin, because CockroachDB privileges derive
-- from ownership. The property is only as strong as custody of the crdb_admin_owner credential.
-- We never claim the table is immutable to everyone.

CREATE ROLE IF NOT EXISTS crdb_admin_owner;
CREATE ROLE IF NOT EXISTS agent_worker;
CREATE ROLE IF NOT EXISTS operator;
CREATE ROLE IF NOT EXISTS forensics_reader;

-- All four tables are owned by the locked-down admin role, so the agent and operator roles
-- cannot ALTER or otherwise escalate on them.
ALTER TABLE agent_memory    OWNER TO crdb_admin_owner;
ALTER TABLE subject_keys    OWNER TO crdb_admin_owner;
ALTER TABLE decision_log    OWNER TO crdb_admin_owner;
ALTER TABLE erasure_record  OWNER TO crdb_admin_owner;

-- agent_worker: writes and reads memory; APPENDS to and reads the decision log; nothing else.
-- Crucially it has NO access to subject_keys (it can never read or destroy a key).
GRANT INSERT, SELECT ON agent_memory TO agent_worker;
GRANT INSERT, SELECT ON decision_log TO agent_worker;
REVOKE UPDATE, DELETE ON decision_log FROM agent_worker;   -- makes the log append-only to the agent

-- operator: executes the erasure procedure only.
GRANT INSERT, SELECT ON decision_log TO operator;
REVOKE UPDATE, DELETE ON decision_log FROM operator;       -- operator also cannot rewrite history
GRANT SELECT, DELETE ON subject_keys TO operator;          -- the erasure = delete the wrapped key row
GRANT SELECT, UPDATE ON agent_memory TO operator;          -- to NULL the live plaintext embedding
GRANT INSERT, SELECT, UPDATE ON erasure_record TO operator;

-- forensics_reader: SELECT only, everywhere, for the genuinely read-only MCP server.
-- (CockroachDB has no column-level privileges; the wrapped_key it can read is cryptographically
--  useless without KMS, and confirm_key_destroyed needs to prove the row is ABSENT.)
GRANT SELECT ON agent_memory   TO forensics_reader;
GRANT SELECT ON subject_keys   TO forensics_reader;
GRANT SELECT ON decision_log   TO forensics_reader;
GRANT SELECT ON erasure_record TO forensics_reader;
