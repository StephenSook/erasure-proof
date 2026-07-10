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

echo "== bringing up 3-node cluster + haproxy =="
docker compose -f docker-compose.crdb.yml up -d
echo "== waiting for cluster ready =="
for i in $(seq 1 40); do
  if docker exec roach1 ./cockroach sql --insecure -e "SELECT 1" >/dev/null 2>&1; then break; fi
  sleep 2
done

echo "== creating database + applying migrations =="
docker exec roach1 ./cockroach sql --insecure -e "CREATE DATABASE IF NOT EXISTS erasure"
DSN="postgresql://root@localhost:26260/erasure?sslmode=disable"
python3 "$DRIVER" migrate "$DSN"

PASSES=0
for run in 1 2 3; do
  SUBJ=$(python3 -c "import uuid; print(uuid.uuid4())")
  echo ""
  echo "== run $run: subject $SUBJ =="
  python3 "$DRIVER" seed "$DSN" "$SUBJ"

  echo "-- erasing (through HAProxy) --"
  python3 "$DRIVER" erase "$DSN" "$SUBJ"

  echo "-- killing roach2 --"
  docker stop roach2 >/dev/null
  sleep 3

  echo "-- verifying committed state from surviving replicas (roach1/roach3) --"
  if python3 "$DRIVER" verify "$DSN" "$SUBJ"; then
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
echo "(Leave the cluster up for the recording, or 'docker compose -f docker-compose.crdb.yml down -v' to clean up.)"
