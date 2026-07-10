"""Read-only forensics MCP server for erasure-proof.

Exposes exactly four read-only tools over a SELECT-only, read-only-transaction database role, each
audit-logged. It never writes. It is distinct from CockroachDB's Managed MCP Server (which the
Bedrock agent uses for select_query); this one packages the erasure-specific forensic checks.
"""
