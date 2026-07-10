"""Signed erasure proof: verifies against the right key, fails on tamper or the wrong key."""

from __future__ import annotations

import pytest

from cryptod import proof, signing


def _sample_proof(pub_pem: str) -> dict:
    return proof.build_proof(
        subject_hash_hex="ab" * 32,
        occurred_at="2026-07-09T00:00:00Z",
        decision_log_seq=7,
        chain_head_hex="cd" * 32,
        wrapped_key_fingerprint_hex="ef" * 32,
        kms_key_arn="arn:aws:kms:us-east-1:1:key/demo",
        key_state="PendingImport",
        signer_public_key_pem=pub_pem,
    )


def test_sign_and_verify_roundtrip() -> None:
    priv = signing.generate_private_key()
    pub = priv.public_key()
    doc = _sample_proof(signing.public_key_pem(pub))
    sig = proof.sign_proof(signing.LocalSigner(priv), doc)
    proof.verify_proof(pub, doc, sig)  # does not raise


def test_tampered_proof_fails() -> None:
    priv = signing.generate_private_key()
    pub = priv.public_key()
    doc = _sample_proof(signing.public_key_pem(pub))
    sig = proof.sign_proof(signing.LocalSigner(priv), doc)

    doc["decision_log_seq"] = 8  # tamper after signing
    with pytest.raises(signing.InvalidSignature):
        proof.verify_proof(pub, doc, sig)


def test_wrong_key_fails() -> None:
    priv = signing.generate_private_key()
    doc = _sample_proof(signing.public_key_pem(priv.public_key()))
    sig = proof.sign_proof(signing.LocalSigner(priv), doc)

    attacker = signing.generate_private_key()
    with pytest.raises(signing.InvalidSignature):
        proof.verify_proof(attacker.public_key(), doc, sig)


def test_canonical_bytes_deterministic() -> None:
    priv = signing.generate_private_key()
    doc = _sample_proof(signing.public_key_pem(priv.public_key()))
    assert proof.canonical_bytes(doc) == proof.canonical_bytes(dict(reversed(list(doc.items()))))


def test_public_key_pem_roundtrip() -> None:
    priv = signing.generate_private_key()
    pem = signing.public_key_pem(priv.public_key())
    loaded = signing.load_public_key_pem(pem)
    assert signing.public_key_pem(loaded) == pem
