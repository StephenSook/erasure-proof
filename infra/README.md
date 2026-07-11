# infra

Infrastructure as code and cloud control-plane scaffolding.

- `ccloud/`: CockroachDB Cloud service-account and RBAC setup, including the control-plane-403
  vs data-plane-privilege demo scripts.
- `aws/`: a standalone KMS + S3 Object Lock smoke script (`kms_s3_smoke.py`), run manually against
  real AWS.

The deployed IAM policies for the three separated principals (KMS/erasure, S3-anchor, Bedrock),
with their confused-deputy conditions, are defined in `deploy/aws/iam.tf`.
