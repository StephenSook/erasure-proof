#!/usr/bin/env bash
# Exercise the JUDGE PATH end to end against the deployed stack, and fail loudly if any judged
# beat has silently degraded.
#
# Why this exists: uptime monitoring answers "is the site up", which is a weaker question than the
# one that decides the submission. The app can be perfectly up while a judged beat is quietly
# broken: the live agent falling back to the recorded verdict because the GPU worker is
# unreachable, the erasure no longer purging the vector, the proof not anchoring, or the hash
# chain no longer intact. None of those turn /healthz red, and a judge would be the first to
# notice, which is exactly what we cannot afford between Aug 19 and Sep 15.
#
# Every assertion is on the SERVER'S OWN reported evidence, never on model prose: `source` must
# name a live provider, and `evidence_proven` is the API's own check of the tool outputs.
#
# This runs the same loop a judge runs with the Autopilot button (store a memory, crypto-erase it,
# then audit it), so it appends one memory and one decision-log row per run. That is the intended
# shape of the demo: the log is append-only and the chain stays intact across runs.
#
# Usage: JUDGE_URL=https://<host> bash infra/judge-path-verify.sh
# The URL is judge-only, so CI passes it as a secret and this script never echoes it.

set -euo pipefail

: "${JUDGE_URL:?set JUDGE_URL to the deployed base URL, no trailing slash}"
command -v jq >/dev/null || { echo "FAIL: jq is required" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  $*"; }

echo "== 1. liveness and database reachability =="
health=$(curl -fsS -m 20 "$JUDGE_URL/healthz") || fail "/healthz did not respond"
echo "$health" | jq -e '.ok == true and .db == true' >/dev/null || fail "/healthz not ok: $health"
note "commit $(echo "$health" | jq -r .commit), db reachable"

echo "== 2. the live agent must be a live provider, not a recorded fallback =="
cfg=$(curl -fsS -m 20 "$JUDGE_URL/api/agent/config") || fail "agent config unreachable"
echo "$cfg" | jq -e '.forensics_available == true' >/dev/null || fail "forensics unavailable: $cfg"
provider=$(echo "$cfg" | jq -r '.provider // ""')
case "$provider" in
  live_*) note "provider $provider" ;;
  *) fail "agent provider is not live: '$provider'. The live agent beat has degraded." ;;
esac

echo "== 3. store a real memory through the real ingest path =="
# The fixture is the repo's own demo memory, so this script carries no embedded payload of its
# own and cannot drift from what the console actually stores.
fixture="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/web/src/data/demoMemory.ts"
[ -f "$fixture" ] || fail "demo memory fixture not found at $fixture"
CONTENT_B64=$(tr -d '\n ' < "$fixture" | sed -n 's/.*contentB64:"\([^"]*\)".*/\1/p')
EMBEDDING_B64=$(tr -d '\n ' < "$fixture" | sed -n 's/.*embeddingB64:"\([^"]*\)".*/\1/p')
[ -n "$CONTENT_B64" ] && [ -n "$EMBEDDING_B64" ] || fail "could not read the demo fixture"
payload=$(jq -n --arg c "$CONTENT_B64" --arg e "$EMBEDDING_B64" '{content:$c, embedding:$e}')
subject=$(curl -fsS -m 60 -X POST -H 'content-type: application/json' \
  -d "$payload" "$JUDGE_URL/memories" | jq -r '.subject_id // empty')
[ -n "$subject" ] || fail "ingest returned no subject_id"
note "stored subject ${subject:0:8}..."

echo "== 4. crypto-erase it, and require the proof to anchor =="
er=$(curl -fsS -m 180 -X POST -H 'content-type: application/json' \
  -d "{\"subject_id\":\"$subject\"}" "$JUDGE_URL/erase") || fail "erase request failed"
echo "$er" | jq -e '.result.decision_log_seq != null' >/dev/null || fail "no decision-log seq: $er"
echo "$er" | jq -e '.proof_ref != null' >/dev/null \
  || fail "the erasure did not anchor a proof (proof_ref is null): $er"
note "seq $(echo "$er" | jq -r .result.decision_log_seq), proof anchored"

echo "== 5. the live vector and the subject key must actually be gone =="
after=$(curl -fsS -m 30 "$JUDGE_URL/api/memory?subject_id=$subject") || fail "memory read failed"
echo "$after" | jq -e '.embedding_present == false' >/dev/null \
  || fail "the live vector SURVIVED the erasure: $after"
echo "$after" | jq -e '(.key_fingerprint // "") == ""' >/dev/null \
  || fail "the subject key row SURVIVED the erasure: $after"
note "vector purged, subject key destroyed"

echo "== 6. warm the scale-to-zero model, as the console does =="
deadline=$(( $(date +%s) + 240 ))
while :; do
  warm=$(curl -fsS -m 30 "$JUDGE_URL/api/agent/warm") || fail "warm endpoint unreachable"
  [ "$(echo "$warm" | jq -r '.warm')" = "true" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && fail "model never warmed within 240s"
  sleep 5
done
note "model warm"

echo "== 7. the audit must be live-sourced and evidence-backed =="
audit=$(curl -fsS -m 300 -X POST -H 'content-type: application/json' \
  -d "{\"subject_id\":\"$subject\"}" "$JUDGE_URL/api/agent/forensics") || fail "audit request failed"
src=$(echo "$audit" | jq -r '.source // ""')
case "$src" in
  live_*) note "source $src" ;;
  *) fail "agent DEGRADED to a non-live source: '$src'. The live beat is broken." ;;
esac
echo "$audit" | jq -e '.evidence_proven == true' >/dev/null \
  || fail "evidence_proven is not true; the server's own check of the tool trace did not pass"
calls=$(echo "$audit" | jq '.tool_calls | length')
[ "$calls" -ge 1 ] || fail "the agent made no real tool calls"
note "evidence_proven true, $calls real tool calls"

echo "== 8. the retained log must still be hash-chain intact =="
chain=$(curl -fsS -m 60 -X POST "$JUDGE_URL/api/verify-chain") || fail "verify-chain unreachable"
echo "$chain" | jq -e '.intact == true' >/dev/null || fail "hash chain is BROKEN: $chain"
note "chain intact over $(echo "$chain" | jq -r .checked) rows"

echo "== 9. the append-only boundary must still deny the agent role =="
rbac=$(curl -fsS -m 60 -X POST "$JUDGE_URL/api/rbac-demo") || fail "rbac-demo unreachable"
echo "$rbac" | jq -e '.denied == true' >/dev/null \
  || fail "the agent role was NOT denied on the append-only log: $rbac"
note "denied with sqlstate $(echo "$rbac" | jq -r '.sqlstate')"

echo
echo "PASS: judge path healthy (live agent, evidence-backed verdict, real erasure, intact chain, enforced boundary)"
