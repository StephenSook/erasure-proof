"""The forensics MCP server: four read-only tools, each audit-logged, over a SELECT-only role.

Run over stdio (the default) for local clients, or streamable HTTP for a deployed endpoint:
    python -m forensics_mcp.server            # stdio
    MCP_TRANSPORT=streamable-http python -m forensics_mcp.server
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from . import audit, db, tools

mcp = FastMCP("erasure-proof-forensics")


@mcp.tool()
def run_readonly_sql(query: str) -> dict:
    """Run a single read-only SELECT against the erasure-proof database and return the rows."""
    audit.audit("run_readonly_sql", {"query": query})
    with db.connect() as conn:
        return tools.run_readonly_sql(conn, query)


@mcp.tool()
def verify_hash_chain() -> dict:
    """Recompute the decision-log hash chain and report whether it is intact and its head hash."""
    audit.audit("verify_hash_chain", {})
    with db.connect() as conn:
        return tools.verify_hash_chain(conn)


@mcp.tool()
def check_erasure_proof(subject_id: str) -> dict:
    """Report the recorded erasure and anchored proof for a subject."""
    audit.audit("check_erasure_proof", {"subject_id": subject_id})
    with db.connect() as conn:
        return tools.check_erasure_proof(conn, subject_id)


@mcp.tool()
def confirm_key_destroyed(subject_id: str) -> dict:
    """Confirm a subject's key row is gone (the crypto-shred) and an erasure was recorded."""
    audit.audit("confirm_key_destroyed", {"subject_id": subject_id})
    with db.connect() as conn:
        return tools.confirm_key_destroyed(conn, subject_id)


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
