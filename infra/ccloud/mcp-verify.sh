#!/usr/bin/env bash
# mcp-verify.sh: verify the decision-log chain head through CockroachDB Cloud's MANAGED MCP
# SERVER (https://cockroachlabs.cloud/mcp), authenticated as a least-privilege service account.
#
# This is the "independent read path" for forensics: the same verification SELECT our own
# read-only MCP server runs, but through Cockroach Labs' hosted endpoint, so a verifier does
# not have to trust our API layer. Every request is audit-logged by CockroachDB Cloud tagged
# `mcp` (their side, not ours).
#
# Auth: a service-account API key (Bearer). The Cloud RBAC check runs per tool call:
# CLUSTER_DEVELOPER alone gets `executing select query: unauthorized`; the operator role
# (ccloud name CLUSTER_OPERATOR_WRITER), scoped to this one cluster, permits read tools.
# Verified live 2026-07-10.
#
# Env (see .env.example): CCLOUD_SA_API_KEY, optionally CRDB_CLUSTER_ID.
#
# Usage: CCLOUD_SA_API_KEY=... bash infra/ccloud/mcp-verify.sh

set -euo pipefail

MCP_URL="https://cockroachlabs.cloud/mcp"
CLUSTER_ID="${CRDB_CLUSTER_ID:-afdd957d-aca2-4af0-9624-a3410c69eb25}"
KEY="${CCLOUD_SA_API_KEY:?set CCLOUD_SA_API_KEY (service-account API key, never committed)}"

post() { # post <json> [session-id]
  curl -sS -m 60 "$MCP_URL" -X POST \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    ${2:+-H "mcp-session-id: $2"} \
    -d "$1"
}

echo "== initialize (MCP streamable HTTP handshake) =="
SID=$(curl -sS -D - -o /dev/null -m 20 "$MCP_URL" -X POST \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"erasure-proof-verify","version":"0.1"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
[ -n "$SID" ] || { echo "FAIL: no mcp-session-id (bad key?)" >&2; exit 1; }
post '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SID" >/dev/null
echo "session established"

echo "== select_query: decision-log chain head via the Managed MCP =="
QUERY="SELECT max(seq) AS chain_len, encode((SELECT hash FROM decision_log ORDER BY seq DESC LIMIT 1),'hex') AS chain_head FROM decision_log"
RESP=$(post "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"select_query\",\"arguments\":{\"cluster_id\":\"$CLUSTER_ID\",\"database\":\"erasure\",\"query\":$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$QUERY")}}}" "$SID")
echo "$RESP" | grep '^data:' | sed 's/^data: //' | python3 -c "
import json, sys
d = json.load(sys.stdin)
if 'error' in d:
    print('DENIED by Cloud RBAC:', d['error']['message'])
    sys.exit(2)
rows = json.loads(d['result']['content'][0]['text'])['rows']
print('chain_len =', rows[0]['chain_len'])
print('chain_head =', rows[0]['chain_head'])
print('PASS: chain head read through cockroachlabs.cloud/mcp (audit-logged server-side)')"
