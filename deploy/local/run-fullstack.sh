#!/usr/bin/env bash
# Full-stack local run: CockroachDB (docker) + cryptod (REAL AWS KMS + S3) + the Go api, so the web
# console at http://localhost:5173 drives the real loop end to end with zero mocks.
#
# Prereqs:
#   - docker, go, uv, and an AWS profile with KMS + S3 access (default: erasure-admin)
#   - the wrapping CMK and the GOVERNANCE dev bucket (see infra/aws/README or the vars below)
#   - an ECDSA P-256 signing key: openssl ecparam -name prime256v1 -genkey -noout -out certs/dev-signing-key.pem
#
# Usage (from the repo root):
#   AWS_PROFILE=erasure-admin KMS_WRAPPING_KEY_ARN=arn:aws:kms:... S3_PROOF_BUCKET=... \
#     bash deploy/local/run-fullstack.sh
# Then in another terminal:  cd web && npm run dev   (no VITE_USE_MOCK: the proxy hits the real api)
# Stop everything:           bash deploy/local/run-fullstack.sh down

set -euo pipefail
cd "$(dirname "$0")/../.."

CONTAINER=ep-fullstack
CRDB_IMAGE=${CRDB_IMAGE:-cockroachdb/cockroach:latest-v25.2}
AWS_PROFILE=${AWS_PROFILE:-erasure-admin}
AWS_REGION=${AWS_REGION:-us-east-1}
SIGNING_KEY=${ECDSA_SIGNING_KEY_PATH:-$PWD/certs/dev-signing-key.pem}
LOG_DIR=${LOG_DIR:-/tmp/erasure-proof-local}

if [[ "${1:-}" == "down" ]]; then
  pkill -f 'uvicorn cryptod.app:app' 2>/dev/null || true
  pkill -f 'go run ./cmd/api' 2>/dev/null || true
  pkill -f 'erasure-proof/services/api' 2>/dev/null || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  echo "full-stack local run stopped"
  exit 0
fi

: "${KMS_WRAPPING_KEY_ARN:?set KMS_WRAPPING_KEY_ARN (the wrapping CMK arn)}"
: "${S3_PROOF_BUCKET:?set S3_PROOF_BUCKET (the GOVERNANCE dev bucket)}"
[[ -f "$SIGNING_KEY" ]] || { echo "missing signing key: $SIGNING_KEY (see prereqs)"; exit 1; }
mkdir -p "$LOG_DIR"

echo "== CockroachDB (single node, insecure; authorization still enforced) =="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" -p 26257:26257 -p 8090:8080 "$CRDB_IMAGE" \
  start-single-node --insecure >/dev/null
for i in $(seq 1 40); do
  docker exec "$CONTAINER" ./cockroach sql --insecure -e "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$CONTAINER" ./cockroach sql --insecure -e "CREATE DATABASE IF NOT EXISTS erasure" >/dev/null
# Core changefeeds (the live decision-log SSE stream) need rangefeeds enabled.
docker exec "$CONTAINER" ./cockroach sql --insecure -e "SET CLUSTER SETTING kv.rangefeed.enabled = true" >/dev/null
for f in db/migrations/0*.sql; do
  echo "   applying $f"
  docker exec -i "$CONTAINER" ./cockroach sql --insecure -d erasure < "$f" >/dev/null
done

echo "== cryptod :8081 (real KMS + S3, GOVERNANCE dev bucket) =="
(
  cd services/cryptod
  AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" \
  KMS_WRAPPING_KEY_ARN="$KMS_WRAPPING_KEY_ARN" \
  S3_PROOF_BUCKET="$S3_PROOF_BUCKET" \
  S3_PROOF_OBJECT_LOCK_MODE=GOVERNANCE S3_PROOF_RETAIN_DAYS=1 \
  ECDSA_SIGNING_KEY_PATH="$SIGNING_KEY" \
  nohup uv run uvicorn cryptod.app:app --port 8081 > "$LOG_DIR/cryptod.log" 2>&1 &
)
for i in $(seq 1 20); do
  curl -sf http://localhost:8081/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://localhost:8081/healthz >/dev/null || { echo "cryptod failed; see $LOG_DIR/cryptod.log"; exit 1; }

echo "== api :8080 (role-scoped pools: operator + agent_worker) =="
(
  cd services/api
  CRDB_DSN_OPERATOR="postgres://operator@localhost:26257/erasure?sslmode=disable" \
  CRDB_DSN_AGENT_WORKER="postgres://agent_worker@localhost:26257/erasure?sslmode=disable" \
  QUERIES_DIR="$PWD/../../db/queries" \
  CRYPTOD_URL=http://localhost:8081 API_PORT=8080 GIT_SHA=local-fullstack \
  nohup go run ./cmd/api > "$LOG_DIR/api.log" 2>&1 &
)
for i in $(seq 1 30); do
  curl -sf http://localhost:8080/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://localhost:8080/healthz >/dev/null || { echo "api failed; see $LOG_DIR/api.log"; exit 1; }

echo
echo "full stack is up:"
echo "  api     http://localhost:8080/healthz   (logs: $LOG_DIR/api.log)"
echo "  cryptod http://localhost:8081/healthz   (logs: $LOG_DIR/cryptod.log)"
echo "  db      postgres://root@localhost:26257/erasure (console :8090)"
echo "next:     cd web && npm run dev            (the console drives the REAL loop)"
echo "stop:     bash deploy/local/run-fullstack.sh down"
