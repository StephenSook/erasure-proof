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

# transformers 4.50.0 breaks vec2text (issue #86); pin to its native era. The default linux torch
# wheel is the CUDA build, so torch.cuda is available on the T4. Let vec2text pull its own
# sentence-transformers/accelerate to avoid resolver conflicts.
image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "torch",
    "vec2text==0.0.13",
    "transformers==4.44.2",
    "numpy",
    "cryptography",
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
    from transformers import AutoModel, AutoTokenizer

    device = "cuda" if torch.cuda.is_available() else "cpu"
    result: dict = {"device": device, "sentence": sentence}

    # Canonical GTR embedding for vec2text: mean-pool the encoder's last hidden state over the
    # attention mask, unnormalized. This is exactly what the pretrained corrector was trained on
    # (SentenceTransformer.encode normalizes and would degrade reconstruction).
    tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/gtr-t5-base")
    base = AutoModel.from_pretrained("sentence-transformers/gtr-t5-base")
    encoder = (base.encoder if hasattr(base, "encoder") else base).to(device).eval()
    corrector = vec2text.load_pretrained_corrector("gtr-base")

    def mean_pool(hidden: "torch.Tensor", mask: "torch.Tensor") -> "torch.Tensor":
        m = mask.unsqueeze(-1).float()
        return (hidden * m).sum(1) / m.sum(1).clamp(min=1e-9)

    def gtr_embed(texts: list[str]) -> "torch.Tensor":
        inp = tokenizer(
            texts, return_tensors="pt", max_length=128, truncation=True, padding="max_length"
        ).to(device)
        with torch.no_grad():
            out = encoder(input_ids=inp["input_ids"], attention_mask=inp["attention_mask"])
            return mean_pool(out.last_hidden_state, inp["attention_mask"])

    # --- The LEAK: embed, then invert at high quality. The name should appear. ---
    emb = gtr_embed([sentence])
    t0 = time.time()
    recovered = vec2text.invert_embeddings(
        embeddings=emb.to(device), corrector=corrector, num_steps=50, sequence_beam_width=8
    )
    result["leak_seconds"] = round(time.time() - t0, 1)
    result["recovered_text"] = recovered[0]

    # --- The ERASURE: AES-256-GCM encrypt the vector, destroy the key, re-invert -> noise. ---
    vec_bytes = emb[0].detach().cpu().numpy().astype("float32").tobytes()  # 768 * 4 = 3072
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, vec_bytes, b"subject-demo")
    del key  # crypto-shred

    noise_floats = np.frombuffer(ct[:3072].ljust(3072, b"\x00"), dtype="float32").copy()
    noise_vec = torch.tensor(noise_floats).unsqueeze(0).to(device)
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
