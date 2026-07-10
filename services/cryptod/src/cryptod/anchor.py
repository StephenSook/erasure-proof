"""Amazon S3 Object Lock: the write-once anchor for erasure proofs.

A signed proof (see proof.py) is written to a versioned, Object-Lock-enabled bucket with a
retention period. In COMPLIANCE mode a protected object version cannot be overwritten or deleted by
any user including the root user, and the retention period cannot be shortened; the only escape is
deleting the whole AWS account. In GOVERNANCE mode a privileged caller with
s3:BypassGovernanceRetention can override it.

Development uses GOVERNANCE with a 1-day retention. COMPLIANCE is irreversible and billed for its
full retention, so it is opted into explicitly only for the production proofs bucket.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import boto3


@dataclass(frozen=True)
class AnchorResult:
    bucket: str
    key: str
    version_id: str
    mode: str
    retain_until: str  # ISO-8601
    sha256: str


class S3Anchor:
    """Thin wrapper over the boto3 S3 client for Object-Lock writes and reads."""

    def __init__(self, region: str, client=None):
        self._s3 = client or boto3.client("s3", region_name=region)

    def anchor(
        self, bucket: str, key: str, body: bytes, mode: str, retain_days: int
    ) -> AnchorResult:
        """Write body to bucket/key under an Object Lock retention. Returns the anchor metadata."""
        if mode not in ("GOVERNANCE", "COMPLIANCE"):
            raise ValueError(f"invalid Object Lock mode {mode!r}")
        retain_until = datetime.now(UTC) + timedelta(days=retain_days)
        digest = hashlib.sha256(body).hexdigest()
        resp = self._s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ObjectLockMode=cast(Literal["GOVERNANCE", "COMPLIANCE"], mode),
            ObjectLockRetainUntilDate=retain_until,
            ContentType="application/json",
        )
        return AnchorResult(
            bucket=bucket,
            key=key,
            version_id=resp.get("VersionId", ""),
            mode=mode,
            retain_until=retain_until.isoformat(),
            sha256=digest,
        )

    def read_retention(self, bucket: str, key: str) -> dict:
        """Return the Object Lock retention metadata for a proof (mode + RetainUntilDate)."""
        resp = self._s3.get_object_retention(Bucket=bucket, Key=key)
        retention = resp.get("Retention", {})
        until = retention.get("RetainUntilDate")
        return {
            "mode": retention.get("Mode", ""),
            "retain_until": until.isoformat() if isinstance(until, datetime) else str(until),
        }

    def read_digest(self, bucket: str, key: str) -> str:
        """SHA-256 of the anchored object's current bytes (to compare against the signed digest)."""
        body = self._s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        return hashlib.sha256(body).hexdigest()
