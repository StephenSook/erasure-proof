# Spike 1 findings: Vec2Text name-then-noise beat

Status: PASS (run 2026-07-09 on a Modal T4 GPU via `spike1_modal.py`)

## Result

- [x] PASS: the curated sentence's name reconstructed verbatim from the embedding, and after
      crypto-erasure the same ciphertext inverted to unreadable noise.
- [ ] FAIL

## Record

| Field | Value |
|-------|-------|
| GPU | Modal T4 (serverless), device=cuda |
| transformers pin | 4.44.2 (below 4.50.0 per issue #86) |
| vec2text | 0.0.13 |
| embedding | canonical GTR mean-pool of the encoder last hidden state (unnormalized) |
| leak num_steps / beam | 50 / 8 |
| demo sentence | "Stephen Sookra is a full-stack developer who builds on CockroachDB and AWS." |
| recovered text (verbatim) | "Stephen Sookra is a full-stack developer who builds on CockroachDB and AWS. " |
| name appeared? | YES, verbatim including the full name |
| leak inversion time | 66.9s |
| post-erasure output | "sssssssssss...s." (unreadable noise, no name) |
| post-erasure readable? | NO |
| erase inversion time | 60.5s |

## What this proves

The headline is real: a person's name is reconstructible from a stored embedding (row deletion is
not enough), and after crypto-erasure the same ciphertext yields only noise. Ran headlessly on a
serverless GPU driven from the terminal, off the AWS critical path.

## Consequence

State 1 (all three spikes PASS): proceed to full build, confidence above 76, no reframe.

## Honesty note

The demo sentence is Stephen's own public bio line (self-consented data, satisfies the
no-third-party-PII rule). It is a curated, in-distribution sentence, so near-verbatim recovery is
expected. Do NOT conflate this with the uncurated 25.5% exact-name-recovery figure from Ghost
Vectors (arXiv 2606.18497): curated in-distribution text reconstructs reliably; uncurated recovery
is roughly 1-in-4. Both statements are true and both appear on the /trust page.

The deployed app serves this as a labeled recorded golden run (see golden_run.json); the live
`InvalidTag` decrypt failure is the actual cryptographic proof and runs live on every erasure.
`spike1_modal.py` is the reproducible artifact.
