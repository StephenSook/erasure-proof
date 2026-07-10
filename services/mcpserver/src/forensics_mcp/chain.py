"""Recompute the decision-log hash chain. This MUST match the Go writer's canonical form byte for
byte (services/api/internal/chain/chain.go): hash = SHA-256(prev_hash || "seq|action|lawful_basis"
|| subject_hash), genesis prev_hash = 32 zero bytes.
"""

from __future__ import annotations

import hashlib

GENESIS_PREV_HASH = b"\x00" * 32


def link(prev_hash: bytes, seq: int, action: str, lawful_basis: str, subject_hash: bytes) -> bytes:
    canonical = f"{seq}|{action}|{lawful_basis}".encode() + subject_hash
    h = hashlib.sha256()
    h.update(bytes(prev_hash))
    h.update(canonical)
    return h.digest()
