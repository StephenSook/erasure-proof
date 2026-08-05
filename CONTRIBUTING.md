# Contributing

Thanks for looking. This is a hackathon project built for the CockroachDB and AWS "Build with
Agentic Memory" hackathon, so the near-term roadmap is set by that deadline. Issues and pull
requests are still welcome, and the guidance below is what the code already holds itself to.

## Running it

`README.md` has the setup and the exact test commands, each verified from a clean clone. Nothing in
the test suites needs a database, AWS credentials, or a `.env`.

## What the code holds itself to

These are not style preferences. They are the properties the project claims, so a change that
breaks one is a change that makes the README untrue.

- **Every SERIALIZABLE transaction has a retry path.** CockroachDB returns `40001` under contention
  and the erasure must not lose either half of destroy-and-retain. Use the `crdbpgx` wrapper.
- **Never persist a plaintext data key, and never log a key, a nonce, or raw personal data.**
  Crypto-erasure is only irreversible if the plaintext key was never written down.
- **Never reuse an AES-GCM (key, nonce) pair.** Fresh 96-bit nonce per encryption.
- **Claims carry evidence.** A non-obvious technical statement in a comment, the README, or the UI
  needs a source: a docs URL, an arXiv id, a spec reference, or a committed transcript. If it
  cannot be evidenced, it gets cut rather than softened.
- **State limitations in the same breath as the capability.** Say "serializable", never "strictly
  serializable". Say that owner and admin keep their privileges by CockroachDB's ownership model,
  so the append-only log is append-only against the agent and operator roles. Say that the
  post-erasure inversion shown in the console is a recorded reproducible run.
- **No mock or placeholder data on a path a judge exercises.** If something is recorded rather than
  live, the UI must label it, and the label must be the truth.
- **No em-dashes in tracked text.** CI enforces this.

## Before opening a pull request

```bash
cd services/api  && go test ./... && go vet ./...
cd services/cryptod && uv run pytest -q && uv run ruff check .
cd web    && npx tsc --noEmit && npx vitest run && npm run lint
cd mobile && npm run typecheck && npm test
```

CI runs ten jobs on every push, plus a nightly node-kill gate that must survive 3 of 3 and a
nightly check that exercises the deployed judged path end to end. A pull request that changes
behaviour should come with the test that would have caught the old behaviour.

## Security

Please do not open a public issue for a security problem. See `SECURITY.md` for the private
reporting path.
