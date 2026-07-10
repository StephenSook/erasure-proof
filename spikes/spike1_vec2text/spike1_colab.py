"""
Spike 1: the Vec2Text name-then-noise beat.  GATES THE HEADLINE.

Run this on Google Colab with a CUDA GPU (Runtime -> Change runtime type -> T4 GPU).
Do NOT run it on the M3: vec2text has no Apple Silicon MPS support and silently falls back
to a slow single core (maintainer confirmed, GitHub issue #72).

Paste each numbered block into its own Colab cell, or run the whole file after `!pip install`.

PASS  = a curated sentence's name reconstructs verbatim/near-verbatim in one GPU run under
        ~1 minute, AND after crypto-erasure the same ciphertext inverts to noise
        (or decryption fails cleanly with InvalidTag and there is no plaintext vector to invert).
FAIL  = reconstruction too garbled to read the name even on a curated sentence, OR no CUDA GPU.
        -> reframe to the fallback concept (poisoned-memory incident response), whose beat does
           not depend on Vec2Text.  Record the outcome in findings.md either way.

Honesty rule for the writeup: never conflate this curated near-verbatim result with the
uncurated 25.5% exact-name-recovery figure from Ghost Vectors (arXiv 2606.18497). Both are true;
say "curated in-distribution text reconstructs reliably; uncurated recovery is roughly 1-in-4".
"""

# --- Cell 1: install (pin transformers below 4.50.0; 4.50.0 breaks vec2text, issue #86) ---
# !pip install -q "vec2text==0.0.13" "sentence-transformers" "transformers<4.50.0"

# --- Cell 2: imports + device check ---
import time
import os
import torch
import vec2text
from sentence_transformers import SentenceTransformer

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"device = {DEVICE}")
if DEVICE != "cuda":
    print("WARNING: no CUDA GPU. On Colab set Runtime -> Change runtime type -> T4 GPU. "
          "CPU inversion is slow; measure it but do not judge PASS/FAIL on CPU timing.")

# --- Cell 3: load GTR-base embedder + pretrained inverter and corrector ---
# The direct load_corrector path avoids the currently-broken Colab notebook (issue #102).
embedder = SentenceTransformer("sentence-transformers/gtr-t5-base")   # 768-dim
corrector = vec2text.load_pretrained_corrector("gtr-base")
# Fallback if the shortcut errors on a checkpoint download:
#   inv = vec2text.models.InversionModel.from_pretrained("jxm/gtr__nq__32")
#   cor = vec2text.models.CorrectorEncoderModel.from_pretrained("jxm/gtr__nq__32__correct")
#   corrector = vec2text.load_corrector(inv, cor)

def embed(texts):
    # GTR-base outputs 768-dim normalized vectors.
    return torch.tensor(embedder.encode(texts, convert_to_numpy=True)).to(DEVICE)

# --- Cell 4: curate ONE short in-distribution sentence containing a name ---
# Use a biographical, in-distribution sentence. This is Stephen's own public bio line
# (self-consented data, satisfies the no-third-party-PII rule). Swap freely.
DEMO_SENTENCE = "Stephen Sookra is a full-stack developer who builds on CockroachDB and AWS."

# --- Cell 5: the LEAK. Embed, then invert. The name should appear. ---
emb = embed([DEMO_SENTENCE])
t0 = time.time()
recovered = vec2text.invert_embeddings(
    embeddings=emb,
    corrector=corrector,
    num_steps=20,              # raise to 50 if garbled (Morris et al.: 92% exact at 50 + beam)
    sequence_beam_width=4,     # raise to 8 if garbled
)
leak_secs = time.time() - t0
print(f"[LEAK] {leak_secs:.1f}s")
print(f"  original : {DEMO_SENTENCE}")
print(f"  recovered: {recovered[0]}")

# --- Cell 6: the ERASURE. AES-256-GCM encrypt the vector, destroy the key, re-invert -> noise. ---
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

vec_bytes = emb[0].detach().cpu().numpy().astype("float32").tobytes()   # 768 * 4 = 3072 bytes
key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)                                                   # 96-bit, fresh
aad = b"subject-demo"                                                    # bound as associated_data
ct = AESGCM(key).encrypt(nonce, vec_bytes, aad)

# Destroy the key (the crypto-erasure). Nothing can decrypt ct now.
del key

# What an attacker has post-erasure is ct: opaque bytes. Reinterpreting the ciphertext as a
# float32 vector and inverting yields noise. (Padding to 768 floats for shape.)
noise_floats = np.frombuffer(ct[: 768 * 4].ljust(768 * 4, b"\x00"), dtype="float32").copy()
noise_vec = torch.tensor(noise_floats).unsqueeze(0).to(DEVICE)
t0 = time.time()
noise_out = vec2text.invert_embeddings(
    embeddings=noise_vec, corrector=corrector, num_steps=20, sequence_beam_width=4,
)
erase_secs = time.time() - t0
print(f"[ERASURE] {erase_secs:.1f}s")
print(f"  ciphertext-as-vector inverts to: {noise_out[0]!r}")
print("  (should be unreadable noise; the name must NOT appear)")

# --- Cell 7: verdict ---
print("\n=== SPIKE 1 VERDICT ===")
print(f"leak inversion time : {leak_secs:.1f}s (target < ~60s on GPU)")
print(f"name recovered      : does '{DEMO_SENTENCE}' name appear in the recovered text above? (human check)")
print(f"post-erasure noise  : is the ciphertext inversion unreadable (no name)? (human check)")
print("Record both human checks, the GPU type, and both timings in spikes/spike1_vec2text/findings.md")
