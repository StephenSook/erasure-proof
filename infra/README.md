# infra

Infrastructure as code and cloud control-plane scaffolding.

- `aws/policies/` — IAM policy documents for the three separated principals (KMS/erasure,
  S3-anchor, Bedrock) with confused-deputy conditions.
- `ccloud/` — CockroachDB Cloud service-account and RBAC setup, including the control-plane-403
  vs data-plane-privilege demo scripts.
