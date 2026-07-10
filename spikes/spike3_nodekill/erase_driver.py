"""
Spike 3 erasure driver (self-contained, psycopg). Proves the atomic erasure-plus-retain
transaction independent of the Go service, so spike 3 runs before the Go build exists.

Subcommands:
  migrate <dsn>        apply db/migrations 0001 + 0002 (roles owner set to root locally)
  seed <dsn> <subj>    seed one subject with encrypted memory + a wrapped key row
  erase <dsn> <subj>   run the SERIALIZABLE erasure transaction with 40001 retry
  verify <dsn> <subj>  assert committed state: decision_log row present, key gone, record present

The erasure transaction is intentionally pure DB + hashing: no KMS/S3/network call inside the
retry closure, so a 40001 retry is always safe.
"""
import hashlib
import os
import random
import sys
import time
import uuid

import psycopg

GENESIS = b"\x00" * 32
MAX_RETRIES = 10


def _connect(dsn):
    return psycopg.connect(dsn, autocommit=False)


def migrate(dsn):
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with psycopg.connect(dsn, autocommit=True) as conn:
        for name in ("0001_schema.sql", "0002_roles.sql"):
            path = os.path.join(here, "db", "migrations", name)
            with open(path) as f:
                sql = f.read()
            # Locally we run as root; ALTER ... OWNER TO crdb_admin_owner still works once the
            # role exists (0002 creates it). Roles have no LOGIN locally for the spike.
            conn.execute(sql)
            print(f"applied {name}")


def seed(dsn, subject_id):
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO subject_keys (subject_id, wrapped_key, kms_key_arn, key_origin, "
            "wrapped_key_fingerprint) VALUES (%s, %s, %s, %s, %s)",
            (subject_id, os.urandom(184), "arn:aws:kms:local:demo", "GENERATE_DATA_KEY",
             hashlib.sha256(os.urandom(32)).digest()),
        )
        conn.execute(
            "INSERT INTO agent_memory (subject_id, content_ciphertext, embedding, "
            "embedding_ciphertext, nonce_content, nonce_embedding, wrapped_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (subject_id, os.urandom(64),
             "[" + ",".join("0.01" for _ in range(768)) + "]",
             os.urandom(3072 + 16), os.urandom(12), os.urandom(12), os.urandom(60)),
        )
    print(f"seeded subject {subject_id}")


def _erase_once(conn, subject_id):
    cur = conn.cursor()
    # 1. Lock the subject key row (FOR UPDATE) and capture its fingerprint.
    cur.execute("SELECT wrapped_key_fingerprint FROM subject_keys WHERE subject_id = %s "
                "FOR UPDATE", (subject_id,))
    row = cur.fetchone()
    if row is None:
        raise RuntimeError("subject key already gone (already erased?)")
    fingerprint = row[0]
    # 2. Chain head.
    cur.execute("SELECT seq, hash FROM decision_log ORDER BY seq DESC LIMIT 1")
    head = cur.fetchone()
    seq = (head[0] + 1) if head else 1
    prev_hash = head[1] if head else GENESIS
    # 3. Append the pseudonymized decision-log row (hash-chained).
    subject_hash = hashlib.sha256(str(subject_id).encode()).digest()
    canonical = f"{seq}|erasure|gdpr_art_17".encode() + subject_hash
    row_hash = hashlib.sha256(bytes(prev_hash) + canonical).digest()
    cur.execute(
        "INSERT INTO decision_log (seq, subject_hash, action, lawful_basis, prev_hash, hash) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (seq, subject_hash, "erasure", "gdpr_art_17", prev_hash, row_hash),
    )
    # 4. Destroy the key (the crypto-shred): delete the only wrapped-key row.
    cur.execute("DELETE FROM subject_keys WHERE subject_id = %s", (subject_id,))
    # 5. NULL the live plaintext embedding (durable copy stays as ciphertext).
    cur.execute("UPDATE agent_memory SET embedding = NULL WHERE subject_id = %s", (subject_id,))
    # 6. Record the erasure.
    cur.execute(
        "INSERT INTO erasure_record (subject_id, decision_log_seq, wrapped_key_fingerprint) "
        "VALUES (%s, %s, %s)",
        (subject_id, seq, fingerprint),
    )
    conn.commit()
    return seq


def erase(dsn, subject_id):
    for attempt in range(MAX_RETRIES):
        conn = _connect(dsn)
        try:
            t0 = time.time()
            seq = _erase_once(conn, subject_id)
            print(f"erased subject {subject_id} at decision_log seq {seq} "
                  f"in {(time.time()-t0)*1000:.1f}ms (attempt {attempt+1})")
            conn.close()
            return
        except psycopg.errors.SerializationFailure:
            conn.rollback()
            conn.close()
            sleep = (2 ** attempt) * 0.1 * (random.random() + 0.5)
            print(f"40001 serialization failure, retrying in {sleep:.2f}s")
            time.sleep(sleep)
        except Exception:
            conn.rollback()
            conn.close()
            raise
    raise RuntimeError("erasure exceeded max retries")


def verify(dsn, subject_id):
    with psycopg.connect(dsn, autocommit=True) as conn:
        key_gone = conn.execute(
            "SELECT count(*) FROM subject_keys WHERE subject_id = %s", (subject_id,)
        ).fetchone()[0] == 0
        log_present = conn.execute(
            "SELECT count(*) FROM decision_log WHERE subject_hash = %s",
            (hashlib.sha256(str(subject_id).encode()).digest(),),
        ).fetchone()[0] > 0
        record_present = conn.execute(
            "SELECT count(*) FROM erasure_record WHERE subject_id = %s", (subject_id,)
        ).fetchone()[0] > 0
        embedding_null = conn.execute(
            "SELECT bool_and(embedding IS NULL) FROM agent_memory WHERE subject_id = %s",
            (subject_id,),
        ).fetchone()[0]
    ok = key_gone and log_present and record_present and embedding_null
    print(f"key_gone={key_gone} log_present={log_present} record_present={record_present} "
          f"embedding_null={embedding_null}  => {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    cmd = sys.argv[1]
    dsn = sys.argv[2]
    if cmd == "migrate":
        migrate(dsn)
    elif cmd == "seed":
        seed(dsn, sys.argv[3])
    elif cmd == "erase":
        erase(dsn, sys.argv[3])
    elif cmd == "verify":
        verify(dsn, sys.argv[3])
    else:
        print(f"unknown command {cmd}")
        sys.exit(1)
