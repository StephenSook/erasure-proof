"""GTREmbedder: canonical gtr-t5-base embedding, matching the pipeline the Vec2Text corrector was
trained on and that db/seed/embed_corpus.py and spike 1 use (unnormalized mean-pool of the encoder's
last hidden state). torch/transformers are imported lazily, so this module imports without them and
the mocked tests never need them; install the package's [ml] extra to use it for real.
"""

from typing import Any

MODEL = "sentence-transformers/gtr-t5-base"


class GTREmbedder:
    def __init__(self) -> None:
        self._torch: Any = None
        self._tokenizer: Any = None
        self._encoder: Any = None

    def _load(self) -> None:
        if self._encoder is not None:
            return
        import torch
        from transformers import AutoModel, AutoTokenizer

        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(MODEL)
        base = AutoModel.from_pretrained(MODEL)
        self._encoder = (base.encoder if hasattr(base, "encoder") else base).eval()

    def embed(self, text: str) -> bytes:
        self._load()
        torch = self._torch
        inp = self._tokenizer(
            [text],
            return_tensors="pt",
            max_length=128,
            truncation=True,
            padding="max_length",
        )
        with torch.no_grad():
            hidden = self._encoder(
                input_ids=inp["input_ids"], attention_mask=inp["attention_mask"]
            ).last_hidden_state
            mask = inp["attention_mask"].unsqueeze(-1).float()
            emb = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
        vec_bytes: bytes = emb[0].detach().cpu().numpy().astype("<f4").tobytes()
        if len(vec_bytes) != 768 * 4:
            raise ValueError(f"expected 3072 embedding bytes, got {len(vec_bytes)}")
        return vec_bytes
