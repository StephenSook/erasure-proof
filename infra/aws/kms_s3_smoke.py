"""Real-AWS smoke for the paths moto cannot test: KMS encryption-context enforcement, the
imported-material kill switch (DeleteImportedKeyMaterial), and S3 Object Lock retention.

Run manually with real AWS credentials. It creates and tears down its own resources and uses
GOVERNANCE + 1-day retention ONLY, never COMPLIANCE (which is unremovable and billed in full).

  PYTHONPATH=services/cryptod/src services/cryptod/.venv/bin/python infra/aws/kms_s3_smoke.py
"""

import os
import sys
import uuid

import boto3

from cryptod.anchor import S3Anchor
from cryptod.kms import KMS

REGION = os.getenv("AWS_REGION", "us-east-1")


def main() -> int:
    kms_client = boto3.client("kms", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    k = KMS(REGION)
    created_keys: list[str] = []
    bucket = f"erasure-proof-smoke-{uuid.uuid4().hex[:16]}"
    obj_key = "smoke/proof.json"
    ok = True

    try:
        # 1. Envelope + encryption-context enforcement (real KMS refuses a mismatched context).
        env_key = kms_client.create_key(Description="erasure-proof-smoke-envelope")["KeyMetadata"][
            "KeyId"
        ]
        created_keys.append(env_key)
        dk = k.generate_data_key(env_key, "subject-A")
        assert k.decrypt_data_key(dk.wrapped, "subject-A") == dk.plaintext
        try:
            k.decrypt_data_key(dk.wrapped, "subject-B")
            print("FAIL: KMS decrypted under the wrong encryption context")
            ok = False
        except Exception as e:  # noqa: BLE001
            print(f"ok: encryption-context mismatch refused ({type(e).__name__})")

        # 2. Imported-material kill switch.
        material = os.urandom(32)
        arn = k.provision_imported_key("erasure-proof-smoke-imported", material)
        created_keys.append(arn)
        before = k.key_state(arn)
        state = k.destroy_imported_key(arn)
        print(f"ok: imported key {before} -> {state} after DeleteImportedKeyMaterial")
        if state != "PendingImport":
            print("FAIL: imported material not destroyed")
            ok = False

        # 3. S3 Object Lock retention (GOVERNANCE, 1 day).
        s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
        res = S3Anchor(REGION).anchor(bucket, obj_key, b'{"smoke":true}', "GOVERNANCE", 1)
        ret = S3Anchor(REGION).read_retention(bucket, obj_key)
        print(f"ok: object lock {ret['mode']} retain_until={ret['retain_until']}")
        if ret["mode"] != "GOVERNANCE":
            print("FAIL: Object Lock retention not applied")
            ok = False
        if S3Anchor(REGION).read_digest(bucket, obj_key) != res.sha256:
            print("FAIL: anchored digest mismatch")
            ok = False

    finally:
        # Teardown. GOVERNANCE objects are removable with BypassGovernanceRetention.
        try:
            versions = s3.list_object_versions(Bucket=bucket).get("Versions", [])
            for v in versions:
                s3.delete_object(
                    Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"],
                    BypassGovernanceRetention=True,
                )
            s3.delete_bucket(Bucket=bucket)
            print("cleaned up S3 bucket")
        except Exception as e:  # noqa: BLE001
            print(f"note: S3 cleanup skipped ({type(e).__name__}: {e})")
        for key_id in created_keys:
            try:
                kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            except Exception as e:  # noqa: BLE001
                print(f"note: could not schedule deletion for {key_id} ({type(e).__name__})")
        print("scheduled KMS keys for deletion (7-day window)")

    print("SMOKE PASS" if ok else "SMOKE FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
