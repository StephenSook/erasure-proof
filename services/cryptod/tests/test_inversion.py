from fastapi.testclient import TestClient

from cryptod import inversion, settings
from cryptod.app import create_app


def _cfg() -> settings.Settings:
    return settings.Settings(
        aws_region="us-east-1",
        kms_wrapping_key_arn="",
        s3_proof_bucket="proofs",
        s3_object_lock_mode="GOVERNANCE",
        s3_retain_days=1,
        ecdsa_signing_key_path="",
    )


def test_recorded_golden_run_shape():
    r = inversion.recorded_golden_run()
    assert r["source"] == "recorded_golden_run"
    assert r["recovered_text"]
    assert r["post_erasure_text"]
    assert len(bytes.fromhex(r["sentence_sha256"])) == 32
    assert r["reproduce"].startswith("modal run")
    assert "InvalidTag" in r["disclosure"]  # the live proof is disclosed, not overclaimed


def test_invert_endpoint_serves_the_golden_run():
    client = TestClient(create_app(_cfg()))
    r = client.get("/invert").json()
    assert r["source"] == "recorded_golden_run"
    assert r["recovered_text"]
    assert r["post_erasure_text"]
