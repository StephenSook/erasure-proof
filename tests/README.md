# tests

- `e2e/` — end-to-end tests that drive the full stack: the append-only rejection test, the
  atomicity test (both-or-neither under an injected 40001 via `inject_retry_errors_enabled`), the
  full write -> erase -> InvalidTag -> proof loop, and the node-kill durability test.

Per-service unit tests live next to their code (for example `services/cryptod/tests`).
