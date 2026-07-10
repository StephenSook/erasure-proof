# Seed corpus (real data, not synthetic)

The demo runs on real GTR-base embeddings of real, self-consented sentences. No synthetic data, no
third-party personal data.

## Files

- `corpus.json` : the source sentences and the consent statement. Every sentence is the author's own
  public bio line (self-consented). Edit here to change the corpus.
- `embed_corpus.py` : computes canonical gtr-t5-base embeddings (unnormalized mean-pool, the exact
  pipeline the Vec2Text corrector was trained on and that `spikes/spike1_vec2text/` used). CPU only.
- `corpus_embedded.json` : the generated artifact, committed so the corpus is reproducible without a
  model download. Per memory: `content_b64`, `embedding_b64` (768 little-endian float32), and
  `embedding_sha256` (so the app can prove a recorded Vec2Text run is of THIS vector).
- `seed.py` : loads the embedded corpus into a running stack via `POST /memories`, so every seeded
  row is produced by the real ingest path (cryptod `/prepare` -> two-level envelope -> one
  SERIALIZABLE transaction), never hand-written ciphertext.

## Regenerate the embeddings

```
uv pip install --python .venv-spikes/bin/python torch transformers==4.44.2 sentencepiece numpy
python db/seed/embed_corpus.py
```

## Load into a running stack

```
API_BASE_URL=http://localhost:8080 python db/seed/seed.py
```

This writes `seeded_subjects.json` (an `id -> subject_id` map). The `demo` subject is the
name-then-noise subject: its sentence matches the recorded Vec2Text golden run
(`spikes/spike1_vec2text/golden_run.json`).

## The golden-run tie (honest note)

The recorded Vec2Text golden run is served as an illustrative, clearly labeled recording; the live
`InvalidTag` decrypt failure is the actual cryptographic proof and runs live on every erasure. To
make the "this recording is of THIS vector" check exact, regenerate the golden run so it also emits
the embedding bytes it inverted, and seed the `demo` subject from those exact bytes (GPU embedding
and CPU embedding can differ in the last float bits, so the byte source must be shared). That final
tie is wired when the frontend `EmbeddingHashCheck` component lands.
