# mcpserver (Python)

A genuinely read-only forensics MCP server (official MCP Python SDK, pinned `mcp>=1.27,<2`).

Exactly four tools, each audit-logged, over a SELECT-only, RLS-scoped `forensics_reader` role:

- `run_readonly_sql`: single-statement SELECT only, with a parse gate and row/time limits.
- `verify_hash_chain`: recompute the decision-log hash chain and compare to the anchored digest.
- `check_erasure_proof`: verify the ECDSA signature and cross-check S3 Object Lock metadata.
- `confirm_key_destroyed`: assert the subject-key row is gone and no unwrap path exists.

Distinct from CockroachDB's Managed MCP Server, which this project uses as an independent
verification path (`infra/ccloud/mcp-verify.sh` reads the chain head through
`cockroachlabs.cloud/mcp`); the in-console forensics agent calls this repo's own read-only tools
directly.
