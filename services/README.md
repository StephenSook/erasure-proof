# services

The runtime services, split by language boundary.

- `api/` — Go. The orchestration layer and the SERIALIZABLE erasure transaction (pgx + the
  official cockroach-go/crdb retry wrapper). Loads SQL from `../db/queries` verbatim.
- `cryptod/` — Python. All key handling: AES-256-GCM envelope crypto, KMS, ECDSA proof signing,
  S3 Object Lock anchoring, GTR embedding, and Vec2Text inversion. Python is mandatory here
  because Vec2Text ships only as PyTorch models.
- `mcpserver/` — Python. The genuinely read-only forensics MCP server (four tools, SELECT-only
  role, audit-logged).
- `agents/` — Python. The Bedrock Claude memory-writer and forensics agents.
