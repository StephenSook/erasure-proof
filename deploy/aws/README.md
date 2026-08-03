# deploy/aws

Infrastructure as code for the judge-facing deployment: one CloudFront URL serving the SPA
(private S3, OAC) and `/api/*` through an ALB to one always-on Fargate task (ARM64, 0.25 vCPU /
2 GB) holding the Go api and cryptod containers. Written for OpenTofu (`brew install opentofu`);
plain Terraform works identically.

NOTHING IN THIS DIRECTORY IS APPLIED AUTOMATICALLY. `tofu apply` creates billable resources
(ALB is the dominant fixed cost). The rehearsal and the real deploy are human decisions.

## Layout

- `versions.tf`, `variables.tf`: providers, region (us-east-1), the erasure-admin profile.
- `main.tf`: default-VPC networking, no NAT (public subnets, SG-to-SG lockdown).
- `alb.tf`: ALB + origin-verify listener rule (403 without the CloudFront-injected header).
- `ecs.tf`: cluster, two-container task definition, service with circuit-breaker rollback.
- `ecr.tf`: immutable-tag repos, keep-last-5 lifecycle.
- `iam.tf`: the three-principal split (svc-base assume-only; role-eraser KMS, role-anchor
  S3 Object Lock with an explicit retention-bypass Deny, role-inference Bedrock).
  `flat_task_role=true` (default) also attaches the three policies directly to the task role so
  the stack works before cryptod's per-client assume-role wiring lands; flip to false after.
- `cdn.tf`: CloudFront (default *.cloudfront.net cert), SPA + `/api/*`, `/memories*`, `/erase*`,
  `/healthz*` behaviors, SPA deep-link error mapping.
- `docker/`: the two Dockerfiles (build from the REPO ROOT) + the cryptod entrypoint that
  materializes the SSM-injected signing key PEM to a file.

## Honest limitations (stated, not hidden)

- CloudFront to ALB is plain HTTP: with no custom domain there is no ACM cert an ALB hostname
  can present. Viewer traffic (browser to CloudFront) is HTTPS. Upgrade path: custom domain +
  ACM cert on the ALB, flip `origin_protocol_policy` to https-only.
- The Object Lock proof bucket is NOT managed here: Object Lock is a bucket-creation-time,
  human decision (GOVERNANCE dev vs COMPLIANCE final). Pass the existing bucket via
  `s3_proof_bucket`.
- The node-kill beat stays on the local 3-node cluster; this stack talks to CockroachDB Cloud.

## Secrets (out of band, never in state)

```sh
AWS_PROFILE=erasure-admin aws ssm put-parameter --type SecureString \
  --name /erasure-proof/crdb-dsn-operator --value '<operator DSN>'
AWS_PROFILE=erasure-admin aws ssm put-parameter --type SecureString \
  --name /erasure-proof/crdb-dsn-agent --value '<agent_worker DSN>'
AWS_PROFILE=erasure-admin aws ssm put-parameter --type SecureString \
  --name /erasure-proof/ecdsa-signing-key --value file://certs/dev-signing-key.pem
AWS_PROFILE=erasure-admin aws ssm put-parameter --type SecureString \
  --name /erasure-proof/modal-invert-secret --value '<Modal inversion bearer secret>'
```

All four parameters must exist BEFORE `tofu apply`: they ride into the containers as ECS
secrets, and ECS fails task startup if any referenced parameter is missing. (The ecdsa key
parameter became optional once KMS signing landed; the stack still reads the other three.)

## Validate (free, no AWS calls)

```sh
cd deploy/aws
tofu init -backend=false
tofu fmt -check
tofu validate
```

## Rehearsal (~$1-3 for a same-day up-and-down; NEEDS STEPHEN'S GO)

1. `tofu init` (local state), `tofu apply -target=aws_ecr_repository.api -target=aws_ecr_repository.cryptod`
2. Build + push both images (repo root):
   ```sh
   aws ecr get-login-password --profile erasure-admin | docker login --username AWS --password-stdin <acct>.dkr.ecr.us-east-1.amazonaws.com
   docker buildx build --platform linux/arm64 -f deploy/aws/docker/api.Dockerfile --build-arg GIT_SHA=$(git rev-parse --short HEAD) -t <ecr-api>:$(git rev-parse --short HEAD) --push .
   docker buildx build --platform linux/arm64 -f deploy/aws/docker/cryptod.Dockerfile -t <ecr-cryptod>:$(git rev-parse --short HEAD) --push .
   ```
3. `tofu apply` with `-var api_image=... -var cryptod_image=... -var kms_wrapping_key_arn=... -var s3_proof_bucket=...`
4. Allowlist the task's public IP on the CockroachDB cluster (ccloud), or open the cluster to
   0.0.0.0/0 temporarily for the rehearsal only.
5. Smoke on the CloudFront URL output: `/healthz` echoes the deployed GIT_SHA, one dry-run
   erasure on a throwaway subject, the console loads, `/proof/:id` verifies in-browser.
6. `tofu destroy` the same day. CloudFront distributions take ~5 min to disable then delete.

## Real deploy (~Aug 1-4 per the calendar; NEEDS STEPHEN'S CONFIRM)

Same steps without the destroy; then wire the GHA keepalive at the CloudFront URL and record
the deployed SHA. Cost steady-state ~$37-54/mo, dominated by the ALB, covered by credits.
