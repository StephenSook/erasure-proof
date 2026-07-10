"""The four read-only forensic checks, as plain functions over a psycopg connection so they can be
unit-tested without an MCP client. The server module wraps these as MCP tools.
"""

from __future__ import annotations

from typing import Any

import psycopg

from . import chain, sqlguard


def _broken(height: int, seq: int, reason: str) -> dict[str, Any]:
    return {"valid": False, "height": height, "broken_at_seq": seq, "reason": reason}


def run_readonly_sql(conn: psycopg.Connection, query: str, max_rows: int = 1000) -> dict[str, Any]:
    """Run a single gated read-only SELECT and return up to max_rows rows."""
    q = sqlguard.assert_single_select(query)
    with conn.cursor() as cur:
        cur.execute(q)  # noqa: S608 -- gated by assert_single_select and the SELECT-only role
        cols = [d.name for d in cur.description] if cur.description else []
        rows = cur.fetchmany(max_rows)
    return {"columns": cols, "rows": [list(r) for r in rows], "row_count": len(rows)}


def verify_hash_chain(conn: psycopg.Connection) -> dict[str, Any]:
    """Recompute the whole decision-log hash chain and report whether it is intact."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT seq, subject_hash, action, lawful_basis, prev_hash, hash "
            "FROM decision_log ORDER BY seq"
        )
        rows = cur.fetchall()
    prev = chain.GENESIS_PREV_HASH
    for seq, subject_hash, action, basis, prev_hash, stored in rows:
        if bytes(prev_hash) != bytes(prev):
            return _broken(len(rows), seq, "prev_hash mismatch")
        expected = chain.link(prev, seq, action, basis, bytes(subject_hash))
        if expected != bytes(stored):
            return _broken(len(rows), seq, "hash mismatch")
        prev = bytes(stored)
    return {"valid": True, "height": len(rows), "head_hash": prev.hex()}


def check_erasure_proof(conn: psycopg.Connection, subject_id: str) -> dict[str, Any]:
    """Report the database-side proof state for a subject. The ECDSA signature verification and S3
    Object Lock check are delegated to cryptod /proof/verify (which holds the signing key and S3
    access); this tool confirms the erasure was recorded and a proof was anchored.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT decision_log_seq, wrapped_key_fingerprint, kms_key_arn, proof_ref, "
            "committed_at FROM erasure_record WHERE subject_id = %s",
            (subject_id,),
        )
        row = cur.fetchone()
    if row is None:
        return {"erased": False}
    seq, fingerprint, kms_key_arn, proof_ref, committed_at = row
    return {
        "erased": True,
        "decision_log_seq": seq,
        "wrapped_key_fingerprint": bytes(fingerprint).hex() if fingerprint else None,
        "kms_key_arn": kms_key_arn,
        "proof_ref": proof_ref,
        "anchored": proof_ref is not None,
        "committed_at": str(committed_at) if committed_at else None,
        "signature_verification": "delegated to cryptod /proof/verify + S3 Object Lock metadata",
    }


def confirm_key_destroyed(conn: psycopg.Connection, subject_id: str) -> dict[str, Any]:
    """Confirm the subject's key row is gone (the crypto-shred) and an erasure was recorded."""
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM subject_keys WHERE subject_id = %s", (subject_id,))
        keys = cur.fetchone()
        cur.execute("SELECT count(*) FROM erasure_record WHERE subject_id = %s", (subject_id,))
        records = cur.fetchone()
    key_present = bool(keys and keys[0] > 0)
    erased = bool(records and records[0] > 0)
    return {
        "key_row_present": key_present,
        "erasure_recorded": erased,
        "destroyed": (not key_present) and erased,
    }
