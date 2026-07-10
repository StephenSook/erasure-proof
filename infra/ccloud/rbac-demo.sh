#!/usr/bin/env bash
# rbac-demo.sh: the three RBAC boundaries, live, with the raw errors on screen. Never conflate
# them: a control-plane denial is a Cloud API 403, an MCP-layer denial is a Cloud RBAC tool
# check, and a data-plane denial is SQLSTATE 42501 from the database itself.
#
#   1. CONTROL PLANE: the forensics service account (cluster-scoped roles only) asks the Cloud
#      API for organization billing info. Denied: it lacks BILLING_COORDINATOR. Read-only
#      probe, nothing destructive is attempted.
#   2. MCP LAYER: every Managed MCP tool call runs a Cloud RBAC check. Observed live
#      2026-07-10: with only CLUSTER_DEVELOPER the select_query tool returns
#      "executing select query: unauthorized"; adding the operator role
#      (CLUSTER_OPERATOR_WRITER) permits read tools. mcp-verify.sh is the allowed path.
#   3. DATA PLANE: the agent_worker SQL role tries to UPDATE the append-only decision_log.
#      Denied with SQLSTATE 42501 by CockroachDB's privilege system (REVOKE UPDATE, DELETE),
#      inside a transaction that always rolls back, so the demo never mutates anything.
#
# Env: CCLOUD_SA_API_KEY (control plane), CRDB_DSN_AGENT_WORKER (data plane; from SSM
# /erasure-proof/crdb-dsn-agent in deployed environments).
#
# Usage: bash infra/ccloud/rbac-demo.sh

set -euo pipefail

KEY="${CCLOUD_SA_API_KEY:?set CCLOUD_SA_API_KEY}"

echo "== 1. control plane: allowed vs denied, same key =="
ALLOWED=$(curl -sS -o /tmp/rbac-clusters.json -w '%{http_code}' -m 20 \
  -H "Authorization: Bearer $KEY" "https://cockroachlabs.cloud/api/v1/clusters" || true)
echo "GET /api/v1/clusters -> HTTP $ALLOWED (cluster-scoped role sees its own cluster)"
DENIED=$(curl -sS -o /tmp/rbac-invoices.json -w '%{http_code}' -m 20 \
  -H "Authorization: Bearer $KEY" "https://cockroachlabs.cloud/api/v1/invoices" || true)
echo "GET /api/v1/invoices -> HTTP $DENIED: $(head -c 120 /tmp/rbac-invoices.json | tr -d '\n')"
if [ "$ALLOWED" = "200" ] && [ "$DENIED" = "403" ]; then
  echo "PASS: same key, 200 on its scoped cluster, 403 on billing (no BILLING_COORDINATOR)"
else
  echo "FAIL: expected 200/403, got $ALLOWED/$DENIED" >&2
  exit 1
fi

echo
echo "== 2. MCP layer: see mcp-verify.sh (allowed path) and its header note (denied path) =="

echo
echo "== 3. data plane: agent_worker attempts UPDATE on the append-only decision_log =="
if [ -z "${CRDB_DSN_AGENT_WORKER:-}" ]; then
  echo "SKIP: set CRDB_DSN_AGENT_WORKER to run the live 42501 (deployed api exposes the same via POST /api/rbac-demo)"
else
  set +e
  OUT=$(cockroach sql --url "$CRDB_DSN_AGENT_WORKER" \
    -e "BEGIN; UPDATE decision_log SET lawful_basis = 'tampered' WHERE seq = 1; ROLLBACK;" 2>&1)
  set -e
  echo "$OUT" | head -3
  if echo "$OUT" | grep -q "42501"; then
    echo "PASS: SQLSTATE 42501, the database itself refuses the tamper"
  else
    echo "FAIL: expected 42501 from the agent role" >&2
    exit 1
  fi
fi
