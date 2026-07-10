-- 0004_rls.sql
-- Row-level security on agent_memory: the agent role can only touch rows for the ONE subject its
-- session declares, so a prompt-injected or buggy agent cannot read or write another person's
-- memory even though its role holds table-wide INSERT/SELECT privileges. Defense in depth on top
-- of the role grants in 0002.
--
-- Mechanics: the session declares its subject with a custom session variable
--   SET app.subject_id = '<uuid>';
-- and the policies compare rows against current_setting('app.subject_id', true). The second
-- argument (missing_ok) makes an UNSET variable return NULL, so a session that never declares a
-- subject matches no rows: fail-closed, verified empirically and enforced in CI (db-smoke).
--
-- Honest limitations (also in SECURITY.md):
--   * RLS binds the agent to the subject its session DECLARES; the application layer chooses that
--     value. It contains cross-subject blast radius, it does not authenticate subjects.
--   * The table owner (crdb_admin_owner) and admin roles bypass RLS; same ownership exemption as
--     the append-only decision log.
--   * RLS is incompatible with CDC queries on the same table, and changefeeds do NOT filter by
--     RLS. We run no changefeed on agent_memory; any future changefeed goes on non-RLS tables.

ALTER TABLE agent_memory ENABLE ROW LEVEL SECURITY;

-- The agent: full CRUD surface it already had, but only within its declared subject. WITH CHECK
-- stops it writing rows for another subject; USING stops it reading them.
CREATE POLICY agent_subject_scope ON agent_memory
    FOR ALL
    TO agent_worker
    USING (subject_id = current_setting('app.subject_id', true)::UUID)
    WITH CHECK (subject_id = current_setting('app.subject_id', true)::UUID);

-- The operator: erasure and provisioning are inherently cross-subject; unrestricted.
CREATE POLICY operator_all ON agent_memory
    FOR ALL
    TO operator
    USING (true)
    WITH CHECK (true);

-- The forensics reader: audits erasures across all subjects; read-only role, read-everything view.
CREATE POLICY forensics_read_all ON agent_memory
    FOR SELECT
    TO forensics_reader
    USING (true);
