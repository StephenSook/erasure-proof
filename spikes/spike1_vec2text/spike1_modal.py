"""
Spike 1 on a serverless GPU (Modal). Runs the Vec2Text name-then-noise beat headlessly on a T4,
so it does not depend on a local GPU (the M3 has none) or a manual Colab session.

One-time setup (Stephen, ~2 min):
    pip install modal
    modal setup            # opens a browser once to authorize this machine

Then run the whole spike from the terminal:
    modal run spikes/spike1_vec2text/spike1_modal.py

Optionally with your own sentence:
    modal run spikes/spike1_vec2text/spike1_modal.py --sentence "Ada Lovelace wrote the first algorithm."

Cost: a single run is a few GPU-minutes on a T4, pennies against Modal's free tier. This file is
also the reproducible artifact the /trust page links to for the recorded golden run.
"""

import json

import modal

# Pin versions per the spike research: transformers 4.50.0 breaks vec2text (issue #86); the default
# linux torch wheel is the CUDA build, so torch.cuda is available on the T4.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch",
        "vec2text==0.0.13",
        "sentence-transformers",
        "transformers<4.50.0",
        "numpy",
        "cryptography",
    )
)

app = modal.App("erasure-proof-spike1", image=image)


@app.function(gpu="T4", timeout=1800)
def run_spike(sentence: str) -> dict:
    import os
    import time

    import numpy as np
    import torch
    import vec2text
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sentence_transformers import SentenceTransformer

    result: dict = {"device": "cuda" if torch.cuda.is_available() else "cpu", "sentence": sentence}

    embedder = SentenceTransformer("sentence-transformers/gtr-t5-base")
    corrector = vec2text.load_pretrained_corrector("gtr-base")

    def embed(texts):
        return torch.tensor(embedder.encode(texts, convert_to_numpy=True)).to(result["device"])

    # --- The LEAK: embed, then invert. The name should appear. ---
    emb = embed([sentence])
    t0 = time.time()
    recovered = vec2text.invert_embeddings(
        embeddings=emb, corrector=corrector, num_steps=20, sequence_beam_width=4
    )
    result["leak_seconds"] = round(time.time() - t0, 1)
    result["recovered_text"] = recovered[0]

    # --- The ERASURE: AES-256-GCM encrypt the vector, destroy the key, re-invert -> noise. ---
    vec_bytes = emb[0].detach().cpu().numpy().astype("float32").tobytes()
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, vec_bytes, b"subject-demo")
    del key  # crypto-shred

    noise_floats = np.frombuffer(ct[: 768 * 4].ljust(768 * 4, b"\x00"), dtype="float32").copy()
    noise_vec = torch.tensor(noise_floats).unsqueeze(0).to(result["device"])
    t0 = time.time()
    noise_out = vec2text.invert_embeddings(
        embeddings=noise_vec, corrector=corrector, num_steps=20, sequence_beam_width=4
    )
    result["erase_seconds"] = round(time.time() - t0, 1)
    result["post_erasure_text"] = noise_out[0]
    return result


@app.local_entrypoint()
def main(sentence: str = "Stephen Sookra is a full-stack developer who builds on CockroachDB and AWS."):
    result = run_spike.remote(sentence)
    print(json.dumps(result, indent=2))
    print("\n=== HUMAN CHECK ===")
    print(f"Does the recovered text contain the name from: {sentence!r}? (PASS if yes)")
    print("Is the post-erasure text unreadable noise with no name? (PASS if yes)")
    print("Record both in spikes/spike1_vec2text/findings.md")
