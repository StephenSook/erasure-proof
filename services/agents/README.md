# agents (Python, Bedrock Claude)

- `memory_writer`: a real Bedrock inference conversation whose output feeds the memory layer, so
  the agent memory is genuinely produced by an agent, not seeded by hand.
- `forensics_agent`: a Bedrock Claude tool-use loop bridged to the read-only MCP client; the
  agentic showcase that verifies an erasure on camera.
