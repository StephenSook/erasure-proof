"""Database connection for the forensics server: a SELECT-only role in a read-only transaction."""

from __future__ import annotations

import os

import psycopg


def dsn() -> str:
    d = os.getenv("CRDB_DSN_FORENSICS_READER") or os.getenv("CRDB_DSN")
    if not d:
        raise RuntimeError("set CRDB_DSN_FORENSICS_READER (a SELECT-only role) or CRDB_DSN")
    return d


def connect() -> psycopg.Connection:
    """Open a read-only connection. default_transaction_read_only is a second guarantee on top of
    the SELECT-only role, so even a mistake in the role grants cannot mutate anything through here.
    """
    conn = psycopg.connect(dsn(), autocommit=True)
    conn.execute("SET default_transaction_read_only = on")
    # A public (bearer-gated) endpoint must not let one expensive SELECT camp on the database;
    # 10s is generous for every forensic query and caps resource-exhaustion abuse.
    conn.execute("SET statement_timeout = '10s'")
    return conn
