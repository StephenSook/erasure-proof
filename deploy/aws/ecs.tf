# One always-on Fargate task (ARM64, 0.25 vCPU / 2 GB) holding both containers: the Go api
# (public, behind the ALB) and cryptod (localhost-only inside the task's network namespace).
# Deployment circuit breaker rolls back a bad deploy automatically.

resource "aws_ecs_cluster" "main" {
  name = local.name
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.name}/api"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "cryptod" {
  name              = "/ecs/${local.name}/cryptod"
  retention_in_days = 7
}

resource "aws_ecs_task_definition" "core" {
  family                   = "${local.name}-core"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 2048
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.svc_base.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name         = "api"
      image        = var.api_image
      essential    = true
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      environment = [
        { name = "API_PORT", value = "8080" },
        { name = "CRYPTOD_URL", value = "http://localhost:8081" },
        { name = "QUERIES_DIR", value = "/db/queries" },
        # Live agent beats. The open-model fallback (llama.cpp on Modal) serves them while the
        # Bedrock quota is zero; empty URL keeps the honest recorded fallback.
        { name = "AGENTS_LLM_URL", value = var.agents_llm_url },
        { name = "AGENTS_LLM_MODEL", value = var.agents_llm_model },
      ]
      secrets = [
        { name = "CRDB_DSN_OPERATOR", valueFrom = "${var.ssm_prefix}/crdb-dsn-operator" },
        { name = "CRDB_DSN_AGENT_WORKER", valueFrom = "${var.ssm_prefix}/crdb-dsn-agent" },
        { name = "AGENTS_LLM_SECRET", valueFrom = "${var.ssm_prefix}/agents-llm-secret" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.api.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "api"
        }
      }
      # No container-level healthCheck on purpose: distroless has no shell or curl, and the
      # binary has no self-check flag. The ALB target group's /healthz probe is the liveness
      # gate that replaces unhealthy tasks.
    },
    {
      name      = "cryptod"
      image     = var.cryptod_image
      essential = true
      environment = [
        { name = "AWS_REGION", value = var.region },
        { name = "KMS_WRAPPING_KEY_ARN", value = var.kms_wrapping_key_arn },
        { name = "S3_PROOF_BUCKET", value = var.s3_proof_bucket },
        { name = "S3_PROOF_OBJECT_LOCK_MODE", value = var.s3_object_lock_mode },
        { name = "CRYPTOD_PORT", value = "8081" },
        { name = "ERASER_ROLE_ARN", value = aws_iam_role.eraser.arn },
        { name = "ANCHOR_ROLE_ARN", value = aws_iam_role.anchor.arn },
        { name = "INFERENCE_ROLE_ARN", value = aws_iam_role.inference.arn },
        # Proofs are signed inside KMS; the private key never exists in this task. This replaces
        # the former SSM SecureString PEM secret (the /ecdsa-signing-key parameter can be deleted
        # at deploy; entrypoint-cryptod.sh tolerates its absence).
        { name = "KMS_SIGNING_KEY_ARN", value = aws_kms_key.proof_signing.arn },
        { name = "S3_PROOF_RETAIN_DAYS", value = tostring(var.s3_retain_days) },
        # The image bakes the recorded run at /app/spikes/...; inversion.py's repo-relative
        # default path does not exist in the container's shallower tree, so pin it explicitly.
        { name = "GOLDEN_RUN_PATH", value = "/app/spikes/spike1_vec2text/golden_run.json" },
        # Live GPU inversion endpoints (Modal, scale-to-zero). Empty values keep cryptod's
        # honest LiveInversionUnavailable fallback; the bearer secret rides in via SSM below.
        { name = "MODAL_INVERT_URL", value = var.modal_invert_url },
        { name = "MODAL_EMBED_URL", value = var.modal_embed_url },
      ]
      secrets = [
        { name = "MODAL_INVERT_SECRET", valueFrom = "${var.ssm_prefix}/modal-invert-secret" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.cryptod.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "cryptod"
        }
      }
    },
  ])
}

resource "aws_ecs_service" "core" {
  name            = "${local.name}-core"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.core.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.public.ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true # no NAT; egress to CockroachDB/KMS/S3/Bedrock/ECR needs a route out
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener_rule.origin_verified]
}
