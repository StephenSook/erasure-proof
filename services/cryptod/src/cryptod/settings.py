"""Runtime configuration for cryptod, from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    aws_region: str
    kms_wrapping_key_arn: str  # the fleet CMK used for GenerateDataKey (envelope path)
    s3_proof_bucket: str
    s3_object_lock_mode: str  # GOVERNANCE (dev) or COMPLIANCE (prod)
    s3_retain_days: int
    ecdsa_signing_key_path: str  # dev only; production uses SSM SecureString or KMS asymmetric sign


def load() -> Settings:
    return Settings(
        aws_region=os.getenv("AWS_REGION", "us-east-1"),
        kms_wrapping_key_arn=os.getenv("KMS_WRAPPING_KEY_ARN", ""),
        s3_proof_bucket=os.getenv("S3_PROOF_BUCKET", "erasure-proof-anchor-dev"),
        # Default to the SAFE mode. COMPLIANCE is irreversible and billed for its full retention,
        # so it must be opted into explicitly for the production bucket.
        s3_object_lock_mode=os.getenv("S3_PROOF_OBJECT_LOCK_MODE", "GOVERNANCE"),
        s3_retain_days=int(os.getenv("S3_PROOF_RETAIN_DAYS", "1")),
        ecdsa_signing_key_path=os.getenv("ECDSA_SIGNING_KEY_PATH", ""),
    )
