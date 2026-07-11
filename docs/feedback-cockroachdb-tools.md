# CockroachDB tools feedback (earned during the build)

Feedback from wiring all four tools into erasure-proof, June 30 to July 10, 2026. Everything
below was observed empirically on CockroachDB Cloud Basic (v25.4) and local v25.2.3; nothing is
speculation.

## Distributed Vector Indexing (C-SPANN)

C-SPANN was a preview in v25.2 (L2-only); it is no longer marked preview in the current stable docs
(v26.2), which document L2, cosine, and inner-product distance. The findings below were observed on
the versions we ran (Basic v25.4, local v25.2.3).


- `feature.vector_index.enabled` CAN be set on the free Basic tier. This was undocumented
  enough that we budgeted a paid-tier fallback we never needed. Worth stating plainly in the
  vector-index docs.
- Filtered search only accelerates when the filter matches the index's prefix columns (issue
  #146145 territory). With a `(subject_id, embedding)` index, prefix-filtered search returned
  full k accelerated; a non-prefix filter fell back to a full scan without warning. An EXPLAIN
  hint or a NOTICE when a vector query silently degrades would save teams real time.
- Converting the indexed table to REGIONAL BY ROW works: "ALTER PRIMARY KEY on a table with
  vector indexes will disable writes to the table while the index is being rebuilt", then the
  index answers correctly afterwards. Since both features are new together, documenting this
  coexistence (and the write-pause during rebuild) would help.
- The single-column-family guidance for vector tables (issue #146046) is easy to miss; we hit
  it only because prior research flagged it.

## Managed MCP Server

- Service-account API key as a Bearer token worked first try against
  `https://cockroachlabs.cloud/mcp`, and the streamable-HTTP session flow matches the MCP spec
  exactly. Smooth.
- Authorization granularity: with only CLUSTER_DEVELOPER, `tools/call select_query` returns
  `{"code": 0, "message": "executing select query: unauthorized"}`. Two small improvements:
  name the missing role in the message, and use a non-zero JSON-RPC error code so clients can
  distinguish authz failures from tool errors programmatically.
- The per-call Cloud RBAC check (deny by default, operator role required for reads) is the
  right design; it gave us a live, honest RBAC demo boundary for free.

## ccloud CLI

- Role-name vocabulary differs between the docs' prose and the CLI: the docs say "Cluster
  Operator", the CLI accepts `CLUSTER_OPERATOR_WRITER` (plus `CLUSTER_DEVELOPER`,
  `CLUSTER_ADMIN`); plain `CLUSTER_OPERATOR` is rejected. The CLI's error listing valid values
  is excellent; aligning the docs' prose with the literal enum would remove a retry.
- `ccloud role add ... -o json` returns no JSON on success (empty stdout); `role get` does.
  Consistent JSON on mutating commands would help scripting.
- Progress spinners write ANSI to stdout even with `-o json` unless `-q` is passed; `-o json`
  alone should imply machine-readable output.
- `service-account api-key create` printing the secret exactly once, with a warning, is the
  right behavior.

## Agent Skills (cockroachlabs/cockroachdb-skills)

- `scripts/validate-spec.py` is a genuinely useful gate; we validated our
  verifying-cryptographic-erasure skill against it before proposing it upstream.
- Two of its checks are naive substring matches that false-positive: the gerund check appends
  "ing" to the first word (flagging valid gerund names), and the third-person check matches
  the "i " inside "AI Act". Your own exemplar skills trigger the same warnings, so tightening
  the matchers would make the signal clean.

## General (Basic tier)

- Publicly trusted TLS on Basic (verify-full with the system CA pool, no per-cluster CA
  download) simplified our container images materially; worth advertising, since the connect
  modal leads with the CA-cert download.
- `SHOW POLICIES FOR TABLE x` is not accepted syntax on v25.2 (the hint says `\h SHOW
  POLICIES`); `pg_policies` works everywhere and is what we scripted against.
- No `array_fill()`: constructing a 768-dim test vector takes a
  `('[' || repeat('0.5,', 767) || '0.5]')::VECTOR(768)` workaround. A vector-literal helper
  would be handy for tests.
