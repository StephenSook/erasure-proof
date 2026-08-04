"""The deployed HTTP transport is judge-token-gated and fails closed without a token."""

import os
from unittest import mock

import pytest
from starlette.testclient import TestClient

from forensics_mcp import server

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def test_http_transport_requires_token() -> None:
    with mock.patch.dict(os.environ, {"MCP_TRANSPORT": "streamable-http"}, clear=False):
        os.environ.pop("MCP_BEARER", None)
        with pytest.raises(SystemExit):
            server.main()


def test_health_is_open_and_everything_else_is_gated() -> None:
    with mock.patch.dict(os.environ, {"MCP_BEARER": "judge-token"}), TestClient(
        server._bearer_wrapped_app()
    ) as client:
        assert client.get("/mcp/health").status_code == 200

        denied = client.post("/mcp", json=INIT, headers=ACCEPT)
        assert denied.status_code == 401

        wrong = client.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer nope"})
        assert wrong.status_code == 401

        ok = client.post(
            "/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer judge-token"}
        )
        assert ok.status_code == 200
        assert ok.headers.get("mcp-session-id")
