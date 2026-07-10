# spikes

The three week-one gating experiments. Each has a `findings.md` with pass/fail results. All three
passed (decision gate State 1: proceed to full build, no reframe).

- `spike1_vec2text/` — the name-then-noise headline. `spike1_modal.py` runs it on a serverless GPU
  (Modal T4); `spike1_colab.py` is the Colab fallback. PASS: a name reconstructed verbatim from the
  embedding, then noise after crypto-erasure. `golden_run.json` is the recorded artifact.
- `spike2_cspann/` — the C-SPANN vector index on the affordable tier. PASS on the free Basic cloud
  tier (database cost $0).
- `spike3_nodekill/` — atomic erasure surviving a node kill. PASS 3/3 via Raft. `erase_driver.py`
  is a self-contained psycopg driver; `run.sh` orchestrates the local cluster.
