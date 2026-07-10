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
    assert prepared["subject_wrapped_key"]
    assert prepared["row_wrapped_key"]
    assert prepared["content_ciphertext"]
    assert len(bytes.fromhex(prepared["subject_key_fingerprint"])) == 32
    # key_origin drives the Go orchestrator's imported-material kill switch; lock it so a drift in
    # what /prepare reports fails loudly.
    assert prepared["key_origin"] == "GENERATE_DATA_KEY"

    anchored = client.post(
        "/anchor",
        json={
            "subject_hash": "ab" * 32,
            "occurred_at": "2026-07-09T00:00:00Z",
            "decision_log_seq": 1,
            "chain_head": "cd" * 32,
            "wrapped_key_fingerprint": prepared["subject_key_fingerprint"],
            "kms_key_arn": key_arn,
            "key_state": "Enabled",
            "merkle_root": "ef" * 32,
            "tree_size": 5,
        },
    ).json()
    assert anchored["signature"]
    assert anchored["proof_ref"].startswith("s3://proofs/")
    assert anchored["object_lock_mode"] == "GOVERNANCE"
    # The Merkle root and tree size are bound into the signed proof (RFC 6962 transparency log).
    assert anchored["proof"]["merkle_root"] == "ef" * 32
    assert anchored["proof"]["tree_size"] == 5

    # proof_canonical is the EXACT byte string the signature covers (what a browser-side WebCrypto
    # verifier checks verbatim). Verify the signature over those bytes directly.
    import base64 as b64mod

    from cryptod import signing as signing_mod

    canonical = b64mod.b64decode(anchored["proof_canonical"])
    pub_key = signing_mod.load_public_key_pem(anchored["signer_public_key_pem"])
    signing_mod.verify(pub_key, b64mod.b64decode(anchored["signature"]), canonical)
    assert anchored["signer_public_key_pem"] == anchored["proof"]["signer_public_key"]

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


def test_compliance_mode_requires_configured_signing_key():
    # An ephemeral signer plus immutable COMPLIANCE storage is a trap; create_app must fail closed.
    import pytest

    from cryptod.app import create_app

    cfg = settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn="",
        s3_proof_bucket="proofs",
        s3_object_lock_mode="COMPLIANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    with pytest.raises(RuntimeError):
        create_app(cfg)


def test_verify_rejects_malformed_input():
    cfg = settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn="",
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    client = TestClient(create_app(cfg))
    r = client.post(
        "/proof/verify",
        json={"proof": {}, "signature": "not-base64!!", "public_key_pem": "not a pem"},
    )
    assert r.status_code == 400


def _plain_cfg(**over):
    base = dict(
        aws_region="us-east-1",
        kms_wrapping_key_arn="",
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    base.update(over)
    return settings.Settings(**base)


def test_invert_config_reports_live_availability():
    # Unconfigured: no live path.
    off = TestClient(create_app(_plain_cfg()))
    assert off.get("/invert/config").json()["live_available"] is False
    # Both set: live path advertised.
    on = TestClient(
        create_app(_plain_cfg(modal_invert_url="https://x.modal.run", modal_invert_secret="s"))  # noqa: S106
    )
    assert on.get("/invert/config").json()["live_available"] is True


def test_invert_live_falls_back_to_recorded_when_unconfigured():
    # No Modal config: /invert/live must NOT hard-fail; it returns the recorded run, flagged.
    client = TestClient(create_app(_plain_cfg()))
    import base64

    emb = base64.b64encode(b"\x00" * 3072).decode()
    r = client.post("/invert/live", json={"embedding": emb})
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "recorded_golden_run"
    assert body["fell_back"] is True
    assert "not configured" in body["fallback_reason"]


def test_invert_live_calls_worker_and_labels_source(monkeypatch):
    # Configured: /invert/live calls the worker and returns source=live_gpu with input_sha256.
    from cryptod import inversion

    def fake_urlopen(req, timeout=0):
        import io
        import json as _json

        payload = _json.loads(req.data.decode())
        assert payload["secret"] == "test-secret"  # noqa: S105
        body = _json.dumps(
            {
                "source": "live_gpu",
                "recovered_text": "the recovered name",
                "seconds": 12.3,
                "device": "cuda",
                "input_sha256": "ab" * 32,
                "num_steps": payload["num_steps"],
                "sequence_beam_width": payload["sequence_beam_width"],
            }
        ).encode()

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return _Resp(body)

    monkeypatch.setattr(inversion.urllib.request, "urlopen", fake_urlopen)
    live_cfg = _plain_cfg(
        modal_invert_url="https://x.modal.run",
        modal_invert_secret="test-secret",  # noqa: S106
    )
    client = TestClient(create_app(live_cfg))
    import base64

    emb = base64.b64encode(b"\x11" * 3072).decode()
    r = client.post(
        "/invert/live", json={"embedding": emb, "num_steps": 30, "sequence_beam_width": 4}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "live_gpu"
    assert body["recovered_text"] == "the recovered name"
    assert body["input_sha256"] == "ab" * 32
    assert body["num_steps"] == 30
    assert "fell_back" not in body


@mock_aws
def test_prepare_two_level_envelope_and_erasure():
    import base64 as b64

    import pytest

    from cryptod import aead, envelope, kms

    key_arn = boto3.client("kms", region_name="us-east-1").create_key()["KeyMetadata"]["Arn"]
    cfg = settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn=key_arn,
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    client = TestClient(create_app(cfg))
    p = client.post(
        "/prepare",
        json={
            "subject_id": "s1",
            "content": b64.b64encode(b"the secret name").decode(),
            "embedding": b64.b64encode(b"\x11" * 3072).decode(),
        },
    ).json()

    # Legitimate read: KMS-decrypt the subject key, unwrap the row key, decrypt the content.
    k = kms.KMS("us-east-1")
    subject_key = k.decrypt_data_key(b64.b64decode(p["subject_wrapped_key"]), "s1")
    row_key = envelope.unwrap_data_key(
        subject_key, envelope.RowKeyMaterial(wrapped=b64.b64decode(p["row_wrapped_key"]))
    )
    content = aead.decrypt(
        row_key,
        aead.Ciphertext(
            nonce=b64.b64decode(p["nonce_content"]), ct=b64.b64decode(p["content_ciphertext"])
        ),
        aad=b"s1",
    )
    assert content == b"the secret name"

    # Erasure deletes the subject_wrapped_key, so the subject key is unrecoverable. Without it the
    # row key that survives in agent_memory can never be unwrapped: the data is dead.
    with pytest.raises(envelope.InvalidUnwrap):
        envelope.unwrap_data_key(
            envelope.new_subject_key(),
            envelope.RowKeyMaterial(wrapped=b64.b64decode(p["row_wrapped_key"])),
        )


@mock_aws
def test_prepare_binds_aad_to_chain_head():
    """The ciphertext is bound to subject_id || chain_head: decrypt succeeds only with the exact
    AAD returned by /prepare, and fails InvalidTag under a tampered chain head."""
    import base64 as b64

    import pytest
    from cryptography.exceptions import InvalidTag

    from cryptod import aead, envelope, kms

    key_arn = boto3.client("kms", region_name="us-east-1").create_key()["KeyMetadata"]["Arn"]
    cfg = settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn=key_arn,
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )
    client = TestClient(create_app(cfg))
    head = "ab" * 32  # a 32-byte chain head, hex
    p = client.post(
        "/prepare",
        json={
            "subject_id": "s1",
            "content": b64.b64encode(b"bound to history").decode(),
            "embedding": b64.b64encode(b"\x11" * 3072).decode(),
            "chain_head": head,
        },
    ).json()
    aad = b64.b64decode(p["aad"])
    assert aad == b"s1" + bytes.fromhex(head)

    k = kms.KMS("us-east-1")
    subject_key = k.decrypt_data_key(b64.b64decode(p["subject_wrapped_key"]), "s1")
    row_key = envelope.unwrap_data_key(
        subject_key, envelope.RowKeyMaterial(wrapped=b64.b64decode(p["row_wrapped_key"]))
    )
    ct = aead.Ciphertext(
        nonce=b64.b64decode(p["nonce_content"]), ct=b64.b64decode(p["content_ciphertext"])
    )
    # Exact AAD: decrypts.
    assert aead.decrypt(row_key, ct, aad=aad) == b"bound to history"
    # Tampered history (different chain head): InvalidTag, even with the right key.
    tampered = b"s1" + bytes.fromhex("cd" * 32)
    with pytest.raises(InvalidTag):
        aead.decrypt(row_key, ct, aad=tampered)

    # Malformed hex is a 400, not a 500.
    r = client.post(
        "/prepare",
        json={
            "subject_id": "s1",
            "content": b64.b64encode(b"x").decode(),
            "embedding": b64.b64encode(b"\x11" * 3072).decode(),
            "chain_head": "not-hex",
        },
    )
    assert r.status_code == 400
