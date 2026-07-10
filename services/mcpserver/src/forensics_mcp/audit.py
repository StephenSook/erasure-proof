"""Audit logging. Every forensic tool call is logged as structured JSON so a reviewer can see who
inspected what. Output goes to the standard logger (stdout/stderr); a deployment can ship it to
CloudWatch or a WORM store.
"""

from __future__ import annotations

import json
import logging

_log = logging.getLogger("forensics_mcp.audit")


def audit(tool: str, args: dict) -> None:
    _log.info(json.dumps({"event": "mcp_tool_call", "tool": tool, "args": args}, default=str))
