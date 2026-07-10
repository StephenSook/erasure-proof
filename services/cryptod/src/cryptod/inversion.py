"""Serve the recorded Vec2Text golden run: the "damage" beat's data source.

The live GPU inversion runs in spikes/spike1_vec2text/spike1_modal.py (Modal T4). This service does
NOT run torch or a model; it serves the recorded, reproducible transcript, clearly labeled as such.
The live cryptographic proof of erasure is the AES-GCM InvalidTag decrypt failure, which runs live
on every erasure; this inversion is the illustrative attack, recorded for a cost-free, reproducible
demo (per the recorded-golden-run disclosure rule).
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib

DISCLOSURE = (
    "Recorded, reproducible Vec2Text run on a GPU. The live proof of erasure is the InvalidTag "
    "decrypt failure, which runs live on every erasure; this inversion is the illustrative attack, "
    "recorded so the demo is reproducible and free to run."
)
REPRODUCE = "modal run spikes/spike1_vec2text/spike1_modal.py"


def _default_path() -> str:
    # src/cryptod/inversion.py -> cryptod -> src -> cryptod(service) -> services -> repo root
    root = pathlib.Path(__file__).resolve().parents[4]
    return str(root / "spikes" / "spike1_vec2text" / "golden_run.json")


def recorded_golden_run(path: str | None = None) -> dict:
    """Load the recorded golden run and return it with disclosure metadata and a content hash.

    The sentence_sha256 lets the frontend cross-check that the recorded run corresponds to the
    subject it is showing (a full embedding-hash check is a should-build once the Modal run is
    re-run to also capture the raw embedding bytes).
    """
    p = path or os.getenv("GOLDEN_RUN_PATH") or _default_path()
    with open(p) as f:
        run = json.load(f)
    sentence = run.get("sentence", "")
    return {
        "source": "recorded_golden_run",
        "disclosure": DISCLOSURE,
        "reproduce": REPRODUCE,
        "sentence": sentence,
        "sentence_sha256": hashlib.sha256(sentence.encode()).hexdigest(),
        "recovered_text": run.get("recovered_text"),
        "post_erasure_text": run.get("post_erasure_text"),
        "leak_seconds": run.get("leak_seconds"),
        "erase_seconds": run.get("erase_seconds"),
        "gpu": run.get("gpu"),
        "recorded_at": run.get("recorded_at"),
        "model": run.get("model"),
    }
