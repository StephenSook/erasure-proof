# Spike 1 findings: Vec2Text name-then-noise beat

Status: NOT RUN YET

Run `spike1_colab.py` on Google Colab with a CUDA GPU (T4 minimum). Fill this in after.

## Result

- [ ] PASS  (curated name reconstructs verbatim/near-verbatim in one GPU run < ~1 min, and
            post-erasure ciphertext inversion is unreadable noise)
- [ ] FAIL  (name too garbled even on a curated sentence, or no CUDA GPU obtainable)

## Record

| Field | Value |
|-------|-------|
| GPU type | (e.g. Colab T4) |
| transformers version pinned | |
| vec2text version | 0.0.13 |
| num_steps / beam width used | 20 / 4 |
| demo sentence | |
| recovered text (verbatim) | |
| name appeared? | |
| leak inversion time | |
| post-erasure output (verbatim) | |
| post-erasure readable? | |
| CPU-only timing (for the deployed-app decision) | |

## Consequence

- PASS -> headline confirmed; proceed. The deployed app serves this as a labeled recorded
  golden run (Option B); the video shows the live GPU inversion.
- FAIL -> the ONLY outcome that changes the project. Reframe to the fallback (poisoned-memory
  incident response, whose visceral beat is the derive-beats-containment moment + the node kill,
  neither of which needs Vec2Text). Re-run the concept lock's flip condition.

## Honesty note

Never present the curated near-verbatim result and the uncurated 25.5% Ghost Vectors figure as
the same thing. State: curated in-distribution text reconstructs reliably; uncurated recovery is
roughly 1-in-4 for exact names (arXiv 2606.18497).
