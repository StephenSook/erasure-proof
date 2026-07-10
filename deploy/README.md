# deploy

- `local/`: the local 3-node CockroachDB cluster plus HAProxy (`docker-compose.yml`,
  `haproxy.cfg`). The failure-domain laboratory: it backs spike 3 and the recorded node-kill demo.
  Bring it up with `make cluster-up`.
- `local/run-fullstack.sh`: the whole real loop on one machine with zero mocks: a single-node
  CockroachDB (migrations + roles applied), cryptod against REAL AWS KMS and the GOVERNANCE dev
  proof bucket, and the Go api on role-scoped pools (operator + agent_worker, so the RBAC denial
  is the real 42501). Then `cd web && npm run dev` drives the console against it. See the header
  of the script for prereqs; `run-fullstack.sh down` stops everything.
- later: the AWS deployment (ECS/Fargate task definitions, S3 + CloudFront, IAM) lives under this
  directory alongside `../infra` for the Terraform/policies.

The managed CockroachDB Cloud cluster is the judge-facing system of record; its nodes are never
killed. The local cluster exists so the node-kill beat can run against real Raft.
