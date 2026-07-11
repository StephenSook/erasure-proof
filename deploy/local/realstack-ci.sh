#!/usr/bin/env bash
# Bring up the real stack against LOCAL FAKES for CI (and local real-stack testing): moto-server
# stands in for AWS KMS + S3 Object Lock, so the loop is genuinely wired (real HTTP, real SQL, real
# AES-GCM + ECDSA + envelope crypto) without touching a paid AWS account. The Modal GPU and Bedrock
# paths are intentionally left unwired; the console serves its honest recorded inversion instead.
#
# Assumes CockroachDB is already up at localhost:26257 with the `erasure` database, all migrations
# applied, and kv.rangefeed.enabled = true (the CI job / caller does this the same way db-smoke
# does). Starts moto-server, cryptod, and the Go api; writes logs under LOG_DIR.
#
#   bash deploy/local/realstack-ci.sh up     # start moto + cryptod + api
#   bash deploy/local/realstack-ci.sh down   # stop them
set -euo pipefail
cd "$(dirname "$0")/../.."

LOG_DIR=${LOG_DIR:-/tmp/erasure-realstack}
MOTO_PORT=${MOTO_PORT:-5000}
AWS_REGION=${AWS_REGION:-us-east-1}
SIGNING_KEY=${SIGNING_KEY:-$LOG_DIR/dev-signing-key.pem}
export AWS_ENDPOINT_URL="http://localhost:${MOTO_PORT}"
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
export AWS_REGION

if [[ "${1:-up}" == "down" ]]; then
  pkill -f 'uvicorn cryptod.app:app' 2>/dev/null || true
  pkill -f 'moto_server' 2>/dev/null || true
  pkill -f 'cmd/api' 2>/dev/null || true
  pkill -f 'exe/api' 2>/dev/null || true
  echo "real stack stopped"
  exit 0
fi

mkdir -p "$LOG_DIR"

echo "== moto-server :${MOTO_PORT} (fake KMS + S3) =="
(
  cd services/cryptod
  uv pip install --quiet 'moto[server]' >/dev/null
  nohup uv run moto_server -p "$MOTO_PORT" > "$LOG_DIR/moto.log" 2>&1 &
)
for i in $(seq 1 30); do
  curl -sf "$AWS_ENDPOINT_URL/moto-api/" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "$AWS_ENDPOINT_URL/moto-api/" >/dev/null || { echo "moto failed; see $LOG_DIR/moto.log"; exit 1; }

echo "== provision the wrapping CMK + the Object Lock bucket in moto =="
KMS_WRAPPING_KEY_ARN=$(
  cd services/cryptod
  uv run python - <<'PY'
import boto3, os
ep = os.environ["AWS_ENDPOINT_URL"]
kms = boto3.client("kms", region_name=os.environ["AWS_REGION"], endpoint_url=ep)
arn = kms.create_key(Description="erasure-proof wrapping CMK")["KeyMetadata"]["Arn"]
s3 = boto3.client("s3", region_name=os.environ["AWS_REGION"], endpoint_url=ep)
s3.create_bucket(Bucket="erasure-proof-anchor-ci", ObjectLockEnabledForBucket=True)
print(arn)
PY
)
echo "   wrapping CMK: $KMS_WRAPPING_KEY_ARN"

echo "== ECDSA P-256 signing key =="
[[ -f "$SIGNING_KEY" ]] || openssl ecparam -name prime256v1 -genkey -noout -out "$SIGNING_KEY" 2>/dev/null

echo "== cryptod :8081 (KMS + S3 via moto, GOVERNANCE) =="
(
  cd services/cryptod
  AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing \
  AWS_REGION="$AWS_REGION" \
  KMS_WRAPPING_KEY_ARN="$KMS_WRAPPING_KEY_ARN" \
  S3_PROOF_BUCKET="erasure-proof-anchor-ci" \
  S3_PROOF_OBJECT_LOCK_MODE=GOVERNANCE S3_PROOF_RETAIN_DAYS=1 \
  ECDSA_SIGNING_KEY_PATH="$SIGNING_KEY" \
  nohup uv run uvicorn cryptod.app:app --host 127.0.0.1 --port 8081 > "$LOG_DIR/cryptod.log" 2>&1 &
)
for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:8081/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://127.0.0.1:8081/healthz >/dev/null || { echo "cryptod failed; see $LOG_DIR/cryptod.log"; tail -20 "$LOG_DIR/cryptod.log"; exit 1; }

echo "== api :8080 (role-scoped pools) =="
(
  cd services/api
  CRDB_DSN_OPERATOR="postgres://operator@localhost:26257/erasure?sslmode=disable" \
  CRDB_DSN_AGENT_WORKER="postgres://agent_worker@localhost:26257/erasure?sslmode=disable" \
  QUERIES_DIR="$PWD/../../db/queries" \
  CRYPTOD_URL=http://127.0.0.1:8081 API_PORT=8080 GIT_SHA=realstack-ci \
  nohup go run ./cmd/api > "$LOG_DIR/api.log" 2>&1 &
)
for i in $(seq 1 90); do
  curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://127.0.0.1:8080/healthz >/dev/null || { echo "api failed; see $LOG_DIR/api.log"; tail -20 "$LOG_DIR/api.log"; exit 1; }

echo "real stack is up (moto + cryptod + api), all wired to CockroachDB"
