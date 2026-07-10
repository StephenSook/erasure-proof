"""S3 Object Lock anchor. moto does not fully implement Object Lock retention reads, so full
retention verification is in the real-AWS smoke; here we cover the digest logic, mode validation,
and that an anchored object round-trips its bytes.
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from cryptod.anchor import S3Anchor


@mock_aws
def test_anchor_writes_and_digest_round_trips():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="proofs", ObjectLockEnabledForBucket=True)
    a = S3Anchor("us-east-1")
    body = b'{"type":"erasure-proof"}'
    res = a.anchor("proofs", "subject/1.json", body, mode="GOVERNANCE", retain_days=1)
    assert res.mode == "GOVERNANCE"
    assert res.sha256 == __import__("hashlib").sha256(body).hexdigest()
    assert a.read_digest("proofs", "subject/1.json") == res.sha256


def test_anchor_rejects_invalid_mode():
    a = S3Anchor("us-east-1")
    with pytest.raises(ValueError):
        a.anchor("b", "k", b"x", mode="NOPE", retain_days=1)
