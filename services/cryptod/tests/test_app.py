"""End-to-end HTTP flow through the cryptod service under moto: prepare -> anchor -> verify."""

from __future__ import annotations

import base64

import boto3
from fastapi.testclient import TestClient
from moto import mock_aws

from cryptod import settings
from cryptod.app import create_app


@mock_aws
def test_prepare_anchor_verify_flow():
    key_arn = boto3.client("kms", region_name="us-east-1").create_key()["KeyMetadata"]["Arn"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="proofs", ObjectLockEnabledForBucket=True)
    cfg = settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn=key_arn,
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    client = TestClient(create_app(cfg))

    assert client.get("/healthz").json()["ok"] is True

    prepared = client.post(
        "/prepare",
        json={
            "subject_id": "subject-1",
            "content": base64.b64encode(b"the person's data").decode(),
            "embedding": base64.b64encode(b"\x00" * 3072).decode(),
        },
    ).json()
    assert prepared["wrapped_key"]
    assert prepared["content_ciphertext"]
    assert len(bytes.fromhex(prepared["wrapped_key_fingerprint"])) == 32

    anchored = client.post(
        "/anchor",
        json={
            "subject_hash": "ab" * 32,
            "occurred_at": "2026-07-09T00:00:00Z",
            "decision_log_seq": 1,
            "chain_head": "cd" * 32,
            "wrapped_key_fingerprint": prepared["wrapped_key_fingerprint"],
            "kms_key_arn": key_arn,
            "key_state": "Enabled",
        },
    ).json()
    assert anchored["signature"]
    assert anchored["proof_ref"].startswith("s3://proofs/")
    assert anchored["object_lock_mode"] == "GOVERNANCE"

    pub = anchored["proof"]["signer_public_key"]
    good = client.post(
        "/proof/verify",
        json={
            "proof": anchored["proof"],
            "signature": anchored["signature"],
            "public_key_pem": pub,
        },
    ).json()
    assert good["valid"] is True

    tampered = dict(anchored["proof"])
    tampered["decision_log_seq"] = 999
    bad = client.post(
        "/proof/verify",
        json={"proof": tampered, "signature": anchored["signature"], "public_key_pem": pub},
    ).json()
    assert bad["valid"] is False
