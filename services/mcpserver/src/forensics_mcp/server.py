"""The forensics MCP server: four read-only tools, each audit-logged, over a SELECT-only role.

Run over stdio (the default) for local clients, or streamable HTTP for a deployed endpoint:
    python -m forensics_mcp.server            # stdio
    MCP_TRANSPORT=streamable-http MCP_BEARER=<token> python -m forensics_mcp.server

The HTTP transport REQUIRES a bearer token (MCP_BEARER) and refuses to start without one:
`run_readonly_sql` can read live rows (including not-yet-erased embeddings), which is exactly the
data class this project protects, so the deployed endpoint is judge-token-gated even though the
role is SELECT-only and every call is audit-logged. stdio keeps no token (a local client already
holds the DSN).
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import audit, db, tools

# The SDK's DNS-rebinding guard rejects Host headers it does not know. Behind CloudFront + an ALB
# the Host is the public distribution domain, so the deploy sets MCP_ALLOWED_HOSTS (comma
# separated); localhost stays allowed for local clients and tests.
_allowed_hosts = ["localhost", "127.0.0.1", "testserver"] + [
    h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()
]
mcp = FastMCP(
    "erasure-proof-forensics",
    transport_security=TransportSecuritySettings(allowed_hosts=_allowed_hosts),
)


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


def _bearer_wrapped_app():
    """The streamable-HTTP ASGI app behind a constant-time bearer check.

    401s carry no body detail; the health probe path (`/mcp/health`) is exempt so a load
    balancer can see liveness without holding the judge token.
    """
    import hmac

    token = os.environ["MCP_BEARER"]
    inner = mcp.streamable_http_app()

    async def app(scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "").rstrip("/") == "/mcp/health":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
            return
        if scope["type"] == "http":
            headers = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in scope.get("headers", [])
            }
            supplied = headers.get("authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {token}"):
                await send({"type": "http.response.start", "status": 401, "headers": []})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await inner(scope, receive, send)

    return app


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        # Fail closed: no token, no public SQL surface.
        if not os.getenv("MCP_BEARER"):
            raise SystemExit("MCP_BEARER is required for the streamable-http transport")
        import uvicorn

        # Read the bind address from our own env, not the SDK settings: the FASTMCP_* env prefix
        # did not reach mcp.settings in the deployed container (observed: uvicorn bound
        # 127.0.0.1:8000 and the load balancer health checks failed), and an explicit read has no
        # such failure mode.
        uvicorn.run(
            _bearer_wrapped_app(),
            host=os.getenv("FASTMCP_HOST", "127.0.0.1"),
            port=int(os.getenv("FASTMCP_PORT", "8000")),
            log_level="info",
        )
        return
    mcp.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
