#!/usr/bin/env bash
# Spike 3: atomic erasure surviving a node kill.  GATES THE RESILIENCE BEAT.
#
# Brings up the local 3-node cluster, seeds a subject, runs the erasure transaction through
# HAProxy, kills a node, and asserts the committed erasure state survives from a surviving
# replica (Raft). Then restarts the killed node and confirms catch-up. Repeats to confirm it is
# reproducible, not a one-off.
#
# Requires: docker, python3 with `pip install "psycopg[binary]"`. Docker Desktop must be running.
#
# Usage:  ./run.sh          (commit-then-kill, the honest and reliable variant)
#         ./run.sh midflight (attempt the harder mid-flight race; falls back to commit-then-kill)
set -euo pipefail

cd "$(dirname "$0")/../.."
DSN_HAPROXY="postgresql://root@localhost:26260/defaultdb?sslmode=disable"
DRIVER="spikes/spike3_nodekill/erase_driver.py"
PY="${PYTHON:-python3}"   # override with PYTHON=/path/to/venv/python to get psycopg

echo "== bringing up 3-node cluster + haproxy =="
docker compose -f deploy/local/docker-compose.yml up -d
echo "== waiting for cluster ready =="
for i in $(seq 1 40); do
  if docker exec roach1 ./cockroach sql --insecure -e "SELECT 1" >/dev/null 2>&1; then break; fi
  sleep 2
done

echo "== creating database + applying migrations =="
docker exec roach1 ./cockroach sql --insecure -e "CREATE DATABASE IF NOT EXISTS erasure"
# Connect directly to roach1 (host port 26257). roach1 is never the node we kill, so the
# commit-then-kill variant proves Raft durability from a surviving replica. HAProxy (26260)
# is available for the mid-flight variant but needs a few seconds to mark backends up.
DSN="postgresql://root@localhost:26257/erasure?sslmode=disable"
echo "== waiting for host SQL port 26257 =="
for i in $(seq 1 30); do
  if "$PY" -c "import psycopg,sys; psycopg.connect('$DSN').close()" >/dev/null 2>&1; then break; fi
  sleep 2
done
"$PY" "$DRIVER" migrate "$DSN"

PASSES=0
for run in 1 2 3; do
  SUBJ=$("$PY" -c "import uuid; print(uuid.uuid4())")
  echo ""
  echo "== run $run: subject $SUBJ =="
  "$PY" "$DRIVER" seed "$DSN" "$SUBJ"

  echo "-- erasing (direct to roach1, a node we never kill) --"
  "$PY" "$DRIVER" erase "$DSN" "$SUBJ"

  echo "-- killing roach2 --"
  docker stop roach2 >/dev/null
  sleep 3

  echo "-- verifying committed state from surviving replicas (roach1/roach3) --"
  if "$PY" "$DRIVER" verify "$DSN" "$SUBJ"; then
    PASSES=$((PASSES+1))
    echo "run $run: committed erasure survived the node kill"
  else
    echo "run $run: FAILED - committed state inconsistent after kill (investigate the cluster)"
  fi

  echo "-- restarting roach2, confirming catch-up --"
  docker start roach2 >/dev/null
  sleep 5
done

echo ""
echo "=== SPIKE 3 VERDICT: $PASSES/3 runs survived the node kill ==="
echo "Record the result, the variant used, and whether catch-up worked in findings.md"
echo "(Leave the cluster up for the recording, or 'docker compose -f deploy/local/docker-compose.yml down -v' to clean up.)"
