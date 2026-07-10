#!/bin/sh
# Fargate can inject secrets only as env vars, but cryptod reads the ECDSA signing key from a
# file path (never logged, never in the image). Materialize the PEM from the env var injected
# out of SSM SecureString, point ECDSA_SIGNING_KEY_PATH at it, then drop the env var.
set -eu
if [ -n "${ECDSA_SIGNING_KEY_PEM:-}" ]; then
  umask 077
  printf '%s' "$ECDSA_SIGNING_KEY_PEM" > /tmp/signing-key.pem
  export ECDSA_SIGNING_KEY_PATH=/tmp/signing-key.pem
  unset ECDSA_SIGNING_KEY_PEM
fi
exec python -m uvicorn cryptod.app:app --host 0.0.0.0 --port "${CRYPTOD_PORT:-8081}"
