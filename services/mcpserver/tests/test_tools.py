"""Tool tests against CockroachDB (skipped without CRDB_DSN_TEST)."""

from __future__ import annotations

import hashlib
import os
import pathlib
import uuid

import psycopg
import pytest

from forensics_mcp import chain, tools


def _repo_root() -> pathlib.Path:
    # tests -> mcpserver -> services -> repo root
    return pathlib.Path(__file__).resolve().parents[3]


def _conn() -> psycopg.Connection:
    dsn = os.getenv("CRDB_DSN_TEST")
    if not dsn:
        pytest.skip("set CRDB_DSN_TEST")
    conn = psycopg.connect(dsn, autocommit=True)
    schema = (_repo_root() / "db" / "migrations" / "0001_schema.sql").read_text()
    conn.execute(schema)
    # Clean slate so the chain is deterministic regardless of other tests sharing the database.
    for t in ("decision_log", "erasure_record", "subject_keys", "agent_memory"):
        conn.execute(f"TRUNCATE TABLE {t}")
    return conn


def _seed_chain(conn: psycopg.Connection, n: int) -> bytes:
    prev = chain.GENESIS_PREV_HASH
    for seq in range(1, n + 1):
        subject_hash = hashlib.sha256(f"subject-{seq}".encode()).digest()
        h = chain.link(prev, seq, "erasure", "gdpr_art_17", subject_hash)
        conn.execute(
            "INSERT INTO decision_log (seq, subject_hash, action, lawful_basis, prev_hash, hash) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (seq, subject_hash, "erasure", "gdpr_art_17", prev, h),
        )
        prev = h
    return prev


def test_verify_hash_chain_valid():
    conn = _conn()
    head = _seed_chain(conn, 3)
    res = tools.verify_hash_chain(conn)
    assert res["valid"] is True
    assert res["height"] == 3
    assert res["head_hash"] == head.hex()


def test_verify_hash_chain_detects_tamper():
    conn = _conn()
    _seed_chain(conn, 3)
    # Rewrite a row's action without recomputing its hash: the chain must no longer verify.
    conn.execute("UPDATE decision_log SET action = 'tampered' WHERE seq = 2")
    res = tools.verify_hash_chain(conn)
    assert res["valid"] is False
    assert res["broken_at_seq"] == 2


def test_confirm_key_destroyed_and_check_proof():
    conn = _conn()
    alive = str(uuid.uuid4())
    erased = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO subject_keys (subject_id, wrapped_key, kms_key_arn, key_origin, "
        "wrapped_key_fingerprint) VALUES (%s, b'\\x01', 'arn:test', 'GENERATE_DATA_KEY', b'\\xaa')",
        (alive,),
    )
    conn.execute(
        "INSERT INTO erasure_record (subject_id, decision_log_seq, wrapped_key_fingerprint, "
        "kms_key_arn, proof_ref) VALUES (%s, 1, b'\\xaa', 'arn:test', 's3://proofs/x.json')",
        (erased,),
    )

    # A subject whose key row is still present is not destroyed.
    r_alive = tools.confirm_key_destroyed(conn, alive)
    assert r_alive["key_row_present"] is True
    assert r_alive["destroyed"] is False

    # A subject with no key row and a recorded erasure is destroyed.
    r_erased = tools.confirm_key_destroyed(conn, erased)
    assert r_erased["destroyed"] is True

    proof = tools.check_erasure_proof(conn, erased)
    assert proof["erased"] is True
    assert proof["anchored"] is True
    assert proof["proof_ref"] == "s3://proofs/x.json"

    assert tools.check_erasure_proof(conn, str(uuid.uuid4()))["erased"] is False


def test_run_readonly_sql_executes_and_gates():
    conn = _conn()
    _seed_chain(conn, 2)
    out = tools.run_readonly_sql(conn, "SELECT count(*) AS n FROM decision_log")
    assert out["rows"][0][0] == 2
    with pytest.raises(ValueError):
        tools.run_readonly_sql(conn, "DELETE FROM decision_log")
