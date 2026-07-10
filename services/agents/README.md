# erasure-agents (Python, Bedrock Claude)

Two Bedrock Claude agents that exercise the memory layer, built on one thin Converse wrapper.

- **MemoryWriter** (`memory_writer.py`): real Claude inference distils the durable fact from a
  conversation turn, then the writer embeds it (canonical gtr-t5-base) and writes it through the real
  ingest path (`POST /memories`). The memory the demo later erases was genuinely agent-written.
- **ForensicsAgent** (`forensics_agent.py`): a Claude tool-use loop wired to the four read-only
  forensics tools (the same ones the MCP server exposes: `confirm_key_destroyed`,
  `check_erasure_proof`, `verify_hash_chain`, `run_readonly_sql`). It gathers evidence and returns a
  `VERDICT: PROVEN` / `VERDICT: NOT PROVEN` result with a tool-call trace.

## Design

Everything the model touches is an injected interface, so the agents are fully unit-tested with a
scripted fake Converser and fake tools, no AWS or database needed:

- `bedrock.py` : `Converser` protocol + `BedrockConverse` (boto3, lazy client). Targets the
  cross-region inference-profile id `us.anthropic.claude-*` (the bare id is not on-demand invokable).
- `embedder.py` : `GTREmbedder`, torch imported lazily (install the `[ml]` extra to use it).
- `store.py` : `HttpMemoryStore` for `POST /memories`.
- `forensics_agent.py` : `ForensicsTools` protocol; the real wiring (a psycopg connection or the MCP
  client) is supplied at the edge.

## Test and lint

```
cd services/agents
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run ruff check src tests && uv run mypy src && uv run pytest -q
```

## Live smoke (needs AWS creds, not in CI)

```
AWS_PROFILE=erasure-admin AWS_REGION=us-east-1 python smoke_bedrock.py
```

A `ThrottlingException` means access works but the low new-account daily-token quota is exhausted, not
that access failed. Keep live agent calls minimal until a Bedrock invocation-tokens quota increase.
