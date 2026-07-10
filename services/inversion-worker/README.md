# inversion-worker

The live Vec2Text inversion GPU worker: the "run the attack yourself" path. A judge inverts the
exact embedding the console is showing, live on a Modal T4, and watches the name reconstruct from
their own click. The recorded golden run stays as the instant, free, reproducible fallback.

- `modal_invert.py`: a Modal app exposing one POST endpoint. Given the base64 raw float32 bytes of
  a GTR-base embedding (3072 bytes), it reconstructs the text with vec2text and returns the
  recovered text, the wall-clock seconds, and the SHA-256 of the exact input bytes, so the caller
  can prove the live run inverted the vector it displays. Auth: a shared secret in the body
  (constant-time compared); only cryptod calls it, judges reach it through our rate-limited API.

## Deploy

```sh
modal secret create erasure-invert-secret INVERT_SECRET=$(openssl rand -hex 24)
modal deploy services/inversion-worker/modal_invert.py     # prints the endpoint URL
```

Then set `MODAL_INVERT_URL` (the printed URL) and `MODAL_INVERT_SECRET` (the same value passed to
the secret) for cryptod. Without them, cryptod's `/invert/live` falls back to the recorded run.

## Cost

A run is a couple of GPU-minutes on a T4 (~$0.02), covered by Modal credits. The image bakes the
GTR encoder and the vec2text corrector so a warm container skips the download; `scaledown_window`
and `max_containers` bound idle and concurrent spend. Cold start (model load) is ~30-60s, the
inversion ~60-90s at 50 steps / beam 8, which is the honest cost of doing the real thing live.

## Reproduce a single run from the terminal

The original spike (`spikes/spike1_vec2text/spike1_modal.py`) runs the full leak-then-noise beat
headlessly and is what the `/trust` page links to as the recorded golden run's provenance.
