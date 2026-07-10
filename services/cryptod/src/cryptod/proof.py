"""The erasure proof document: what gets signed and anchored in S3 Object Lock.

The proof is a small, canonical-JSON object over the facts of one erasure. It is signed with
ECDSA P-256 (signing.py) and its digest is written to write-once storage. A verifier can later
recompute the canonical bytes, check the signature, and cross-check the anchored digest, without
any trust in the database operator.

Canonicalization: JSON with sorted keys and no insignificant whitespace, UTF-8 encoded. This makes
the signed bytes deterministic so verification does not depend on serializer quirks.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from . import signing

__all__ = ["build_proof", "canonical_bytes", "sign_proof", "verify_proof", "NIST_CONDITION"]

# The exact honest condition on crypto-erasure, stated in the proof itself.
NIST_CONDITION = (
    "NIST SP 800-88 Rev. 2 cryptographic erase (Purge). Irreversible only if the plaintext data "
    "key was never persisted and no wrapped key or key material was backed up, escrowed, or "
    "stored externally."
)


def build_proof(
    *,
    subject_hash_hex: str,
    occurred_at: str,
    decision_log_seq: int,
    chain_head_hex: str,
    wrapped_key_fingerprint_hex: str,
    kms_key_arn: str,
    key_state: str,
    signer_public_key_pem: str,
    merkle_root_hex: str = "",
    tree_size: int = 0,
) -> dict[str, Any]:
    """Assemble the proof object. All bytes fields are hex so the proof is JSON-clean. The RFC 6962
    Merkle root and tree size (when supplied) bind the proof to the transparency-log state, so a
    verifier can prove any decision-log entry is included in the tree this proof signed."""
    proof: dict[str, Any] = {
        "version": 1,
        "type": "erasure-proof",
        "subject_hash": subject_hash_hex,
        "occurred_at": occurred_at,
        "decision_log_seq": decision_log_seq,
        "decision_log_head": chain_head_hex,
        "wrapped_key_fingerprint": wrapped_key_fingerprint_hex,
        "kms_key_arn": kms_key_arn,
        "kms_key_state": key_state,
        "nist_condition": NIST_CONDITION,
        "signer_public_key": signer_public_key_pem,
    }
    if merkle_root_hex:
        proof["merkle_root"] = merkle_root_hex
        proof["tree_size"] = tree_size
    return proof


def canonical_bytes(proof: dict[str, Any]) -> bytes:
    """Deterministic serialization of the proof for signing and verification.

    ensure_ascii=True keeps the canonical form pure ASCII, so the browser verifier's
    string -> TextEncoder round trip can never disagree with these bytes over non-ASCII content.
    """
    return json.dumps(proof, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_proof(signer: signing.ProofSigner, proof: dict[str, Any]) -> bytes:
    """Sign the canonical proof bytes. The signer may hold the key locally (LocalSigner) or
    delegate to KMS (KmsSigner); the signature format and verification path are identical."""
    return signer.sign(canonical_bytes(proof))


def verify_proof(
    public_key: ec.EllipticCurvePublicKey, proof: dict[str, Any], signature: bytes
) -> None:
    """Raise InvalidSignature if the proof does not verify against the public key."""
    signing.verify(public_key, signature, canonical_bytes(proof))
