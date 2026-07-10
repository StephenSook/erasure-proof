# Three-principal IAM. The task role (svc_base) holds exactly ONE power: sts:AssumeRole into
# three narrowly scoped roles, so no single credential can both destroy a key and write a proof
# and invoke a model. Confused-deputy hardening: every trust policy pins aws:PrincipalAccount.
#
# flat_task_role=true (rehearsal default) ALSO attaches the three capability policies directly
# to svc_base so the stack works before cryptod's per-client assume-role wiring lands. Flip to
# false once cryptod assumes ERASER_ROLE_ARN / ANCHOR_ROLE_ARN / INFERENCE_ROLE_ARN itself.
# Until that flip ships in production, judge surfaces describe this as "capability-scoped
# policies, split into three assumable principals" and nothing stronger.

# --- execution role: pull images, write logs, read SSM secrets (infra plumbing, not app power)

resource "aws_iam_role" "task_execution" {
  name = "${local.name}-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_ssm" {
  name = "read-app-secrets"
  role = aws_iam_role.task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameters", "ssm:GetParameter"]
      Resource = "arn:aws:ssm:${var.region}:${local.account_id}:parameter${var.ssm_prefix}/*"
    }]
  })
}

# --- task role: assume-only base

resource "aws_iam_role" "svc_base" {
  name = "${local.name}-svc-base"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "svc_base_assume" {
  name = "assume-capability-roles-only"
  role = aws_iam_role.svc_base.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Resource = [
        aws_iam_role.eraser.arn,
        aws_iam_role.anchor.arn,
        aws_iam_role.inference.arn,
      ]
    }]
  })
}

# --- the three capability roles, each assumable ONLY by svc_base

locals {
  capability_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.svc_base.arn }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:PrincipalAccount" = local.account_id }
      }
    }]
  })
}

# role-eraser: the KMS destroy capability. Envelope ops on the wrapping CMK are DENIED unless
# the call carries a subject_id encryption context (the confused-deputy check the CMK policy
# also enforces); the imported-material kill switch is scoped to project-tagged keys.
resource "aws_iam_role" "eraser" {
  name               = "${local.name}-role-eraser"
  assume_role_policy = local.capability_trust
}

resource "aws_iam_role_policy" "eraser" {
  name = "kms-envelope-and-import-kill-switch"
  role = aws_iam_role.eraser.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnvelopeOpsRequireSubjectContext"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = var.kms_wrapping_key_arn
        Condition = {
          "Null" = { "kms:EncryptionContext:subject_id" = "false" }
        }
      },
      {
        Sid      = "DescribeWrappingKey"
        Effect   = "Allow"
        Action   = ["kms:DescribeKey"]
        Resource = var.kms_wrapping_key_arn
      },
      {
        Sid    = "ImportedMaterialLifecycleOnProjectKeys"
        Effect = "Allow"
        Action = [
          "kms:GetParametersForImport",
          "kms:ImportKeyMaterial",
          "kms:DeleteImportedKeyMaterial",
          "kms:DescribeKey",
          "kms:ScheduleKeyDeletion",
          "kms:TagResource",
        ]
        Resource = "arn:aws:kms:${var.region}:${local.account_id}:key/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/project" = "erasure-proof" }
        }
      },
      {
        # CreateKey cannot be resource-scoped; constrain to EXTERNAL-origin keys so this role
        # can only mint import-material kill-switch keys, not general-purpose CMKs.
        Sid      = "CreateExternalOriginKeysOnly"
        Effect   = "Allow"
        Action   = ["kms:CreateKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "kms:KeyOrigin" = "EXTERNAL" }
        }
      },
    ]
  })
}

# role-anchor: write proofs to the Object Lock bucket, never bypass retention.
resource "aws_iam_role" "anchor" {
  name               = "${local.name}-role-anchor"
  assume_role_policy = local.capability_trust
}

resource "aws_iam_role_policy" "anchor" {
  name = "object-lock-proof-writes"
  role = aws_iam_role.anchor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProofObjects"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:PutObjectRetention",
          "s3:GetObjectRetention",
        ]
        Resource = "arn:aws:s3:::${var.s3_proof_bucket}/*"
      },
      {
        Sid      = "BucketMeta"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"]
        Resource = "arn:aws:s3:::${var.s3_proof_bucket}"
      },
      {
        Sid      = "NeverBypassRetention"
        Effect   = "Deny"
        Action   = ["s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = "arn:aws:s3:::${var.s3_proof_bucket}/*"
      },
    ]
  })
}

# role-inference: invoke Claude on Bedrock (cross-region inference profiles), nothing else.
resource "aws_iam_role" "inference" {
  name               = "${local.name}-role-inference"
  assume_role_policy = local.capability_trust
}

resource "aws_iam_role_policy" "inference" {
  name = "bedrock-invoke-claude-only"
  role = aws_iam_role.inference.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource = [
        "arn:aws:bedrock:${var.region}:${local.account_id}:inference-profile/${var.bedrock_model_prefix}*",
        "arn:aws:bedrock:*::foundation-model/anthropic.*",
      ]
    }]
  })
}

# --- rehearsal shim: attach the capability policies directly to the task role

resource "aws_iam_role_policy" "flat_eraser" {
  count  = var.flat_task_role ? 1 : 0
  name   = "flat-eraser"
  role   = aws_iam_role.svc_base.id
  policy = aws_iam_role_policy.eraser.policy
}

resource "aws_iam_role_policy" "flat_anchor" {
  count  = var.flat_task_role ? 1 : 0
  name   = "flat-anchor"
  role   = aws_iam_role.svc_base.id
  policy = aws_iam_role_policy.anchor.policy
}

resource "aws_iam_role_policy" "flat_inference" {
  count  = var.flat_task_role ? 1 : 0
  name   = "flat-inference"
  role   = aws_iam_role.svc_base.id
  policy = aws_iam_role_policy.inference.policy
}
