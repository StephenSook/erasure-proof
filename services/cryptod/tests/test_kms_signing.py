"""KmsSigner: proofs signed inside KMS verify with the standard path, and misconfigurations fail
at construction (boot), not on the first erasure.

moto's KMS implements MessageType=RAW faithfully (hash-then-sign, like real AWS); its DIGEST mode
re-hashes the digest, which is why KmsSigner uses RAW (see signing.py). These tests would catch a
regression to DIGEST immediately: nothing could verify the signatures.
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from cryptod import proof, signing

REGION = "us-east-1"


def _make_key(key_spec: str = "ECC_NIST_P256", key_usage: str = "SIGN_VERIFY") -> str:
    kms = boto3.client("kms", region_name=REGION)
    return kms.create_key(KeySpec=key_spec, KeyUsage=key_usage)["KeyMetadata"]["Arn"]


@mock_aws
def test_kms_sign_verifies_with_standard_path() -> None:
    signer = signing.KmsSigner(_make_key(), REGION)
    payload = b"canonical proof bytes"
    sig = signer.sign(payload)
    pub = signing.load_public_key_pem(signer.public_key_pem)
    signing.verify(pub, sig, payload)  # does not raise


@mock_aws
def test_kms_signed_proof_roundtrip_and_tamper() -> None:
    signer = signing.KmsSigner(_make_key(), REGION)
    doc = proof.build_proof(
        subject_hash_hex="ab" * 32,
        occurred_at="2026-07-10T00:00:00Z",
        decision_log_seq=9,
        chain_head_hex="cd" * 32,
        wrapped_key_fingerprint_hex="ef" * 32,
        kms_key_arn="arn:aws:kms:us-east-1:1:key/demo",
        key_state="PendingImport",
        signer_public_key_pem=signer.public_key_pem,
    )
    sig = proof.sign_proof(signer, doc)
    pub = signing.load_public_key_pem(signer.public_key_pem)
    proof.verify_proof(pub, doc, sig)  # does not raise

    doc["decision_log_seq"] = 10  # tamper after signing
    with pytest.raises(signing.InvalidSignature):
        proof.verify_proof(pub, doc, sig)


@mock_aws
def test_kms_signature_indistinguishable_from_local_verify_path() -> None:
    """The whole point of the shared interface: a verifier cannot (and need not) know which signer
    produced the proof. Both must verify through the identical code path."""
    payload = b"same bytes either way"

    kms_signer = signing.KmsSigner(_make_key(), REGION)
    local_signer = signing.LocalSigner(signing.generate_private_key())

    for signer in (kms_signer, local_signer):
        pub = signing.load_public_key_pem(signer.public_key_pem)
        signing.verify(pub, signer.sign(payload), payload)


@mock_aws
def test_wrong_key_spec_fails_at_boot() -> None:
    # A symmetric key cannot sign; the misconfiguration must surface at construction.
    arn = _make_key(key_spec="SYMMETRIC_DEFAULT", key_usage="ENCRYPT_DECRYPT")
    with pytest.raises(Exception):  # noqa: B017 - moto raises a client error before our checks
        signing.KmsSigner(arn, REGION)


@mock_aws
def test_rsa_sign_key_rejected_at_boot() -> None:
    # An RSA SIGN_VERIFY key answers GetPublicKey but is not ECDSA_SHA_256; our own check rejects.
    arn = _make_key(key_spec="RSA_2048", key_usage="SIGN_VERIFY")
    with pytest.raises(ValueError, match="ECDSA_SHA_256"):
        signing.KmsSigner(arn, REGION)


@mock_aws
def test_oversized_payload_guard() -> None:
    signer = signing.KmsSigner(_make_key(), REGION)
    with pytest.raises(ValueError, match="4096"):
        signer.sign(b"x" * 4097)
