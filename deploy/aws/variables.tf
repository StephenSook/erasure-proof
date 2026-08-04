variable "region" {
  description = "Everything lives in one region (the CockroachDB cluster is aws-us-east-1)."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS CLI profile. Never the root account (use erasure-admin)."
  type        = string
  default     = "erasure-admin"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "erasure-proof"
}

variable "api_image" {
  description = "Full ECR image URI for the Go api container (pushed before apply)."
  type        = string
}

variable "cryptod_image" {
  description = "Full ECR image URI for the cryptod container (pushed before apply)."
  type        = string
}

variable "kms_wrapping_key_arn" {
  description = "The existing fleet wrapping CMK (created 2026-07-10, alias/erasure-proof-wrapping)."
  type        = string
}

variable "s3_proof_bucket" {
  description = <<-EOT
    The EXISTING Object Lock proof bucket. Deliberately NOT managed here: Object Lock must be
    enabled at bucket creation and the retention mode decision (GOVERNANCE dev vs COMPLIANCE
    near submission) is made by a human, never by an apply.
  EOT
  type        = string
}

variable "s3_object_lock_mode" {
  description = "GOVERNANCE for every rehearsal. COMPLIANCE only for the final judge-facing bucket."
  type        = string
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.s3_object_lock_mode)
    error_message = "Must be GOVERNANCE or COMPLIANCE."
  }
}

variable "ssm_prefix" {
  description = <<-EOT
    SSM Parameter Store prefix holding the secrets, created OUT OF BAND by the runbook (never in
    state): <prefix>/crdb-dsn-operator, <prefix>/crdb-dsn-agent (SecureString DSNs) and
    <prefix>/ecdsa-signing-key (SecureString PEM).
  EOT
  type        = string
  default     = "/erasure-proof"
}

variable "flat_task_role" {
  description = <<-EOT
    true (rehearsal default): the three capability policies (eraser / anchor / inference) attach
    DIRECTLY to the task role, so the stack works before cryptod's assume-role wiring lands.
    false (production hardening): the task role keeps ONLY sts:AssumeRole into the three scoped
    roles; cryptod must then assume ERASER_ROLE_ARN / ANCHOR_ROLE_ARN / INFERENCE_ROLE_ARN per
    client. The three roles exist either way; only the attachment moves.
  EOT
  type        = bool
  default     = true
}

variable "bedrock_model_prefix" {
  description = "Inference-profile prefix the agents invoke (cross-region profile ids)."
  type        = string
  default     = "us.anthropic."
}

variable "modal_invert_url" {
  description = "Modal inversion endpoint URL (non-secret). Empty keeps the honest live-inversion-unavailable fallback."
  type        = string
  default     = ""
}

variable "modal_embed_url" {
  description = "Modal GTR embed endpoint URL (non-secret). Empty keeps the honest fallback."
  type        = string
  default     = ""
}

variable "agents_llm_url" {
  description = "OpenAI-compatible open-model endpoint for the live agent beats (llama.cpp on Modal). Empty keeps the honest recorded fallback. Requires <ssm_prefix>/agents-llm-secret in SSM."
  type        = string
  default     = ""
}

variable "agents_llm_model" {
  description = "Model label sent to the open-model endpoint and shown in provenance."
  type        = string
  default     = "qwen2.5-3b-instruct"
}

variable "s3_retain_days" {
  description = <<-EOT
    Per-object Object Lock retention days cryptod stamps on anchored proofs. 1 for GOVERNANCE
    rehearsals; ~50 for the judged COMPLIANCE bucket (covers judging through Sep 15 plus buffer;
    COMPLIANCE retention is unremovable until it expires, so never set it long casually).
  EOT
  type        = number
  default     = 1
}
