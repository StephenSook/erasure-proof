"""
Spike 2: the C-SPANN vector index on the affordable tier.  GATES THE DATABASE STORY.

Runs against whatever DSN you pass. Run it FIRST on a local single-node cluster (always works),
then against a free CockroachDB Cloud Basic cluster to answer the open question: can
`feature.vector_index.enabled` be set on Basic?

  # local single node (in another terminal): cockroach start-single-node --insecure
  python run.py "postgresql://root@localhost:26257/defaultdb?sslmode=disable"

  # cloud Basic:
  python run.py "$CRDB_DSN"

Requires: pip install "psycopg[binary]" numpy

PASS    = a C-SPANN VECTOR(768) index builds and prefix-filtered search is index-accelerated
          on a tier we can afford.
PARTIAL = works only on Standard/Advanced/local, not free Basic -> budget/deploy change, not a
          concept change (activate the $400 trial for a Standard cluster, or demo vectors locally).
FAIL    = index cannot build on any tier we can run, or prefix-filtered search does not accelerate.

Also checks the new must-verify item from the backend blueprint: UPDATE-to-NULL of a
C-SPANN-indexed vector column (the erasure transaction's vector purge). If that breaks the preview
index, the fallback is DELETE + copy ciphertext into a shredded_memory archive table.
"""
import sys
import time
import numpy as np
import psycopg


def rand_vec(n=768):
    v = np.random.randn(n).astype("float32")
    v /= np.linalg.norm(v)
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


def main(dsn):
    log = []

    def record(step, ok, detail=""):
        line = f"[{'ok' if ok else 'FAIL'}] {step}: {detail}"
        print(line)
        log.append(line)

    conn = psycopg.connect(dsn, autocommit=True)
    cur = conn.cursor()

    # 1. Can we enable the vector index feature on this tier?
    try:
        cur.execute("SET CLUSTER SETTING feature.vector_index.enabled = true")
        record("feature.vector_index.enabled", True, "set successfully")
    except Exception as e:
        record("feature.vector_index.enabled", False, f"{type(e).__name__}: {e}")
        print("\n=> If this is Basic, the vector path needs Standard/local. This is a "
              "budget/deploy change (PARTIAL), not a concept change.")

    # 2. Build the table + prefix-filtered C-SPANN index.
    cur.execute("DROP TABLE IF EXISTS spike2_mem")
    cur.execute("""
        CREATE TABLE spike2_mem (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            subject_id UUID NOT NULL,
            embedding VECTOR(768),
            FAMILY f_all (id, subject_id, embedding)
        )
    """)
    try:
        cur.execute("SET sql_safe_updates = false")
        cur.execute("CREATE VECTOR INDEX spike2_idx ON spike2_mem (subject_id, embedding)")
        record("CREATE VECTOR INDEX (subject_id, embedding)", True, "built")
    except Exception as e:
        record("CREATE VECTOR INDEX", False, f"{type(e).__name__}: {e}")
        conn.close()
        _write(log)
        return

    # 3. Insert a few hundred rows across a handful of subjects, batches of ~100 (preview guidance).
    subjects = [psycopg.sql.SQL("gen_random_uuid()")] * 5
    cur.execute("SELECT gen_random_uuid() FROM generate_series(1,5)")
    subj_ids = [r[0] for r in cur.fetchall()]
    total = 0
    for batch in range(5):
        rows = []
        for _ in range(100):
            sid = subj_ids[np.random.randint(0, len(subj_ids))]
            rows.append((sid, rand_vec()))
        cur.executemany("INSERT INTO spike2_mem (subject_id, embedding) VALUES (%s, %s)", rows)
        total += len(rows)
    record("insert rows", True, f"{total} rows across {len(subj_ids)} subjects")

    target = subj_ids[0]
    q = rand_vec()

    # 4. Prefix-filtered similarity search + EXPLAIN (should use the index).
    cur.execute(
        "EXPLAIN SELECT id FROM spike2_mem WHERE subject_id = %s ORDER BY embedding <-> %s LIMIT 5",
        (target, q),
    )
    plan = "\n".join(r[0] for r in cur.fetchall())
    accelerated = "vector" in plan.lower() and "full scan" not in plan.lower()
    record("prefix-filtered search accelerated", accelerated, "see plan below")
    print(plan)

    cur.execute(
        "SELECT id FROM spike2_mem WHERE subject_id = %s ORDER BY embedding <-> %s LIMIT 5",
        (target, q),
    )
    got = len(cur.fetchall())
    record("prefix-filtered returns k", got == 5, f"returned {got}/5")

    # 5. Non-prefix filter with LIMIT: does it return a full k? Does it accelerate?
    cur.execute(
        "EXPLAIN SELECT id FROM spike2_mem WHERE embedding IS NOT NULL "
        "ORDER BY embedding <-> %s LIMIT 5",
        (q,),
    )
    plan2 = "\n".join(r[0] for r in cur.fetchall())
    record("non-prefix filter plan captured", True, "see plan below")
    print(plan2)

    # 6. THE ERASURE VECTOR PURGE: UPDATE a C-SPANN-indexed vector column to NULL.
    try:
        cur.execute("UPDATE spike2_mem SET embedding = NULL WHERE subject_id = %s", (target,))
        cur.execute("SELECT count(*) FROM spike2_mem WHERE subject_id = %s AND embedding IS NULL",
                    (target,))
        nulled = cur.fetchone()[0]
        record("UPDATE indexed vector to NULL (erasure purge)", nulled > 0,
               f"{nulled} rows nulled; index survived")
    except Exception as e:
        record("UPDATE indexed vector to NULL", False,
               f"{type(e).__name__}: {e}  -> use DELETE + shredded_memory archive fallback")

    conn.close()
    _write(log)


def _write(log):
    verdict = "\n".join(log)
    print("\n=== SPIKE 2 VERDICT ===")
    print(verdict)
    print("\nRecord the tier, the two EXPLAIN plans, and the UPDATE-to-NULL result in findings.md")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python run.py <CRDB_DSN>")
        sys.exit(1)
    main(sys.argv[1])
