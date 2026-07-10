"""Bedrock Claude agents for erasure-proof.

Two agents, both driven by the same thin Converse wrapper:
  - MemoryWriter: uses real Claude inference to distil a durable memory from a conversation turn,
    then embeds it and writes it through the real ingest path (POST /memories).
  - ForensicsAgent: a Claude tool-use loop wired to the read-only forensics tools (the same four the
    MCP server exposes), which gathers evidence and returns a PROVEN / NOT PROVEN verdict.
"""
