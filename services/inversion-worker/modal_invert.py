"""Live Vec2Text inversion on a Modal serverless GPU (T4).

This is the "run the attack yourself" endpoint: given the raw bytes of a GTR-base embedding, it
reconstructs the text on a real GPU, live, from the caller's request. The demo console offers it
next to the recorded golden run so a judge does not have to trust our recording: they invert the
EXACT same vector (same sha256) live and watch the name appear, then erase and invert the
ciphertext to noise.

Design and cost guards:
  * The GTR encoder and the vec2text corrector are baked into the image at build time
    (download_models), so a warm container inverts without re-downloading weights.
  * gpu="T4", a short scaledown window, and a small max_containers cap bound the spend: a run is
    a couple of GPU-minutes (~$0.02) and the container idles down quickly. Our backend is the
    only caller (Bearer secret required); judges reach it only through our rate-limited API.
  * transformers is pinned below 4.50 (4.50 breaks vec2text, issue #86); the embedding is the
    canonical unnormalized mean-pool the corrector was trained on.

Deploy:  modal deploy services/inversion-worker/modal_invert.py
Secret:  modal secret create erasure-invert-secret INVERT_SECRET=<random>
The deploy prints the endpoint URL; set MODAL_INVERT_URL + MODAL_INVERT_SECRET for cryptod.
"""

from __future__ import annotations

import modal


def download_models() -> None:
    from transformers import AutoModel, AutoTokenizer
    import vec2text

    AutoTokenizer.from_pretrained("sentence-transformers/gtr-t5-base")
    AutoModel.from_pretrained("sentence-transformers/gtr-t5-base")
    vec2text.load_pretrained_corrector("gtr-base")


image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch",
        "vec2text==0.0.13",
        "transformers==4.44.2",
        "numpy",
        "fastapi[standard]",
    )
    .run_function(download_models)
)

app = modal.App("erasure-proof-invert", image=image)


@app.cls(
    gpu="T4",
    timeout=300,
    scaledown_window=120,
    max_containers=2,
    secrets=[modal.Secret.from_name("erasure-invert-secret")],
)
class Inverter:
    @modal.enter()
    def load(self) -> None:
        import torch
        import vec2text
        from transformers import AutoModel, AutoTokenizer

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/gtr-t5-base")
        base = AutoModel.from_pretrained("sentence-transformers/gtr-t5-base")
        self.encoder = (base.encoder if hasattr(base, "encoder") else base).to(self.device).eval()
        self.corrector = vec2text.load_pretrained_corrector("gtr-base")

    @modal.fastapi_endpoint(method="POST")
    def invert(self, data: dict):
        import base64
        import hashlib
        import hmac
        import os
        import time

        import numpy as np
        import torch
        import vec2text
        from fastapi import HTTPException

        # Only our backend knows the secret (cryptod sends it in the body over TLS); judges reach
        # this endpoint only through our rate-limited API, never directly. Constant-time compare.
        secret = os.environ.get("INVERT_SECRET", "")
        presented = str(data.get("secret", ""))
        if not secret or not hmac.compare_digest(presented, secret):
            raise HTTPException(status_code=401, detail="unauthorized")

        try:
            raw = base64.b64decode(data["embedding_b64"], validate=True)
        except Exception as exc:  # noqa: BLE001 (surface the decode failure as a 400)
            raise HTTPException(status_code=400, detail=f"bad embedding_b64: {exc}") from exc
        if len(raw) != 768 * 4:
            raise HTTPException(status_code=400, detail=f"embedding must be 3072 bytes, got {len(raw)}")

        num_steps = int(data.get("num_steps", 50))
        beam = int(data.get("sequence_beam_width", 8))
        num_steps = max(1, min(num_steps, 60))
        beam = max(1, min(beam, 8))

        vec = np.frombuffer(raw, dtype="<f4").copy()
        emb = torch.tensor(vec).unsqueeze(0).to(self.device)
        t0 = time.time()
        recovered = vec2text.invert_embeddings(
            embeddings=emb, corrector=self.corrector, num_steps=num_steps, sequence_beam_width=beam
        )
        return {
            "source": "live_gpu",
            "recovered_text": recovered[0],
            "seconds": round(time.time() - t0, 1),
            "device": self.device,
            "input_sha256": hashlib.sha256(raw).hexdigest(),
            "num_steps": num_steps,
            "sequence_beam_width": beam,
        }
