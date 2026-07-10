"""Load the real embedded seed corpus into a running erasure-proof stack via POST /memories.

This is deliberately NOT a raw SQL seed: the memory rows must be produced by the real ingest path
(cryptod /prepare -> two-level envelope -> one SERIALIZABLE transaction), so the seeded data is
genuinely encrypted, not hand-written ciphertext.

Prerequisite: the api service (and cryptod, cluster, KMS) must be up. Run embed_corpus.py first.

Usage:
    API_BASE_URL=http://localhost:8080 python db/seed/seed.py
    # prints the subject_id assigned to each memory (capture the 'demo' one for the demo page)
"""

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

SEED_DIR = pathlib.Path(__file__).resolve().parent
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8080").rstrip("/")


def post_memory(content_b64: str, embedding_b64: str) -> dict:
    # API_BASE_URL is operator-controlled and must be http(s); guard the scheme so this is never
    # pointed at a file: or custom scheme.
    if not API_BASE_URL.startswith(("http://", "https://")):
        raise ValueError(f"API_BASE_URL must be http(s), got {API_BASE_URL!r}")
    body = json.dumps({"content": content_b64, "embedding": embedding_b64}).encode()
    req = urllib.request.Request(  # noqa: S310 - scheme guarded above
        f"{API_BASE_URL}/memories",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - scheme guarded above
        return json.loads(resp.read())


def main() -> None:
    path = SEED_DIR / "corpus_embedded.json"
    if not path.exists():
        sys.exit("corpus_embedded.json not found; run: python db/seed/embed_corpus.py")
    corpus = json.loads(path.read_text())

    print(f"seeding {len(corpus['memories'])} memories to {API_BASE_URL}")
    assigned = {}
    for mem in corpus["memories"]:
        try:
            res = post_memory(mem["content_b64"], mem["embedding_b64"])
        except urllib.error.HTTPError as e:
            sys.exit(f"seed failed for {mem['id']}: HTTP {e.code} {e.read().decode()[:200]}")
        assigned[mem["id"]] = res["subject_id"]
        print(f"  {mem['id']:12s} -> subject_id={res['subject_id']} memory_id={res['memory_id']}")

    (SEED_DIR / "seeded_subjects.json").write_text(json.dumps(assigned, indent=2) + "\n")
    print("wrote seeded_subjects.json (id -> subject_id map for the demo page)")


if __name__ == "__main__":
    main()
