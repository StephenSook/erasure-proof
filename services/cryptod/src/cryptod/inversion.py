"""Serve the recorded Vec2Text golden run: the "damage" beat's data source.

The live GPU inversion runs in spikes/spike1_vec2text/spike1_modal.py (Modal T4). This service does
NOT run torch or a model; it serves the recorded, reproducible transcript, clearly labeled as such.
The live cryptographic proof of erasure is the AES-GCM InvalidTag decrypt failure, which runs live
on every erasure; this inversion is the illustrative attack, recorded for a cost-free, reproducible
demo (per the recorded-golden-run disclosure rule).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.request

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


class LiveInversionUnavailable(RuntimeError):
    """The Modal GPU worker is not configured or did not answer; the caller should fall back."""


def live_inversion(
    embedding_b64: str,
    *,
    modal_url: str,
    modal_secret: str,
    num_steps: int = 50,
    sequence_beam_width: int = 8,
    timeout_s: float = 280.0,
) -> dict:
    """Invert an embedding on the Modal T4 GPU worker (services/inversion-worker/modal_invert.py).

    Returns the recovered text with source="live_gpu" and the input_sha256 the worker computed, so
    the frontend can prove the live run inverted the exact vector it is showing. Raises
    LiveInversionUnavailable on any misconfiguration or transport/HTTP failure so /invert/live can
    fall back to the recorded golden run without ever surfacing a hard 500.
    """
    if not modal_url or not modal_secret:
        raise LiveInversionUnavailable("MODAL_INVERT_URL / MODAL_INVERT_SECRET not configured")
    try:
        base64.b64decode(embedding_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise LiveInversionUnavailable(f"bad embedding_b64: {exc}") from exc

    payload = json.dumps(
        {
            "secret": modal_secret,
            "embedding_b64": embedding_b64,
            "num_steps": num_steps,
            "sequence_beam_width": sequence_beam_width,
        }
    ).encode()
    req = urllib.request.Request(  # noqa: S310 (fixed https Modal URL, not user-controlled)
        modal_url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise LiveInversionUnavailable(f"modal worker call failed: {exc}") from exc

    if not body.get("recovered_text"):
        raise LiveInversionUnavailable("modal worker returned no recovered_text")
    body.setdefault("source", "live_gpu")
    body["disclosure"] = (
        "Live Vec2Text inversion on a Modal T4 GPU, run from this request. input_sha256 is the "
        "SHA-256 of the exact embedding bytes inverted, so you can confirm it matches the vector "
        "shown. The live proof of erasure remains the AES-GCM InvalidTag failure."
    )
    return body
