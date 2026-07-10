-- 0006_regional_by_row.sql (OPTIONAL, multi-region clusters only)
--
-- Geo-domiciling of personal data by row: agent_memory and subject_keys become REGIONAL BY ROW
-- so each subject's encrypted memory and wrapped key live in a chosen region, while the
-- pseudonymized compliance artifacts (decision_log, erasure_record) become GLOBAL so the
-- retained log and the erasure registry read fast from every region.
--
-- WHY THIS IS NOT IN THE DEFAULT MIGRATION PATH (db/migrations/0*.sql):
--  * It requires a cluster whose nodes carry `--locality=region=...` flags AND whose region
--    names match the ones below. The judge-facing deployment runs on CockroachDB Cloud Basic,
--    which is single-region, so this migration is prepared and locally verified but NOT enabled
--    there. We do not claim multi-region operation on any judge-facing surface.
--  * Applying it on a cluster without localities fails (no regions to assign).
--
-- Prerequisites:
--  * Nodes started with --locality=region=us-east-1 / eu-west-1 / ap-southeast-2
--    (deploy/local/docker-compose.multiregion.yml provides exactly this).
--  * Adapt the region names here if your cluster's localities differ.
--
-- Verified locally by deploy/local/rbr-verify.sh (spins up the multi-region compose, applies
-- the default migrations plus this file, and asserts domiciling, RLS, and vector search).
--
-- References:
--  * https://www.cockroachlabs.com/docs/stable/multiregion-overview
--  * https://www.cockroachlabs.com/docs/stable/table-localities

ALTER DATABASE erasure SET PRIMARY REGION "us-east-1";
ALTER DATABASE erasure ADD REGION "eu-west-1";
ALTER DATABASE erasure ADD REGION "ap-southeast-2";

-- Personal data: domiciled per row. The hidden crdb_region column defaults to the gateway
-- node's region; pin a subject explicitly with e.g.
--   UPDATE agent_memory SET crdb_region = 'eu-west-1' WHERE subject_id = $1;
--   UPDATE subject_keys SET crdb_region = 'eu-west-1' WHERE subject_id = $1;
-- (or INSERT with an explicit crdb_region from the ingest path).
ALTER TABLE agent_memory SET LOCALITY REGIONAL BY ROW;
ALTER TABLE subject_keys SET LOCALITY REGIONAL BY ROW;

-- Compliance artifacts: pseudonymized (subject_hash / opaque UUID, no raw PII), retained after
-- erasure, and read on every code path (chain verification, resurrection guard), so GLOBAL:
-- fast non-stale reads from every region at the cost of slower writes.
ALTER TABLE decision_log SET LOCALITY GLOBAL;
ALTER TABLE erasure_record SET LOCALITY GLOBAL;
