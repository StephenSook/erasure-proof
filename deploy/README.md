# deploy

- `local/` — the local 3-node CockroachDB cluster plus HAProxy (`docker-compose.yml`,
  `haproxy.cfg`). The failure-domain laboratory: it backs spike 3 and the recorded node-kill demo.
  Bring it up with `make cluster-up`.
- later: the AWS deployment (ECS/Fargate task definitions, S3 + CloudFront, IAM) lives under this
  directory alongside `../infra` for the Terraform/policies.

The managed CockroachDB Cloud cluster is the judge-facing system of record; its nodes are never
killed. The local cluster exists so the node-kill beat can run against real Raft.
