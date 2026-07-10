# The proof-signing key: KMS asymmetric ECC_NIST_P256 (SIGN_VERIFY). The ECDSA private key is
# generated inside KMS and never leaves it; cryptod holds only kms:Sign + kms:GetPublicKey (via
# the anchor capability), so a compromised task can ask for signatures while compromised but can
# never exfiltrate the key that makes proofs attributable. Every Sign call lands in CloudTrail.
#
# This supersedes the SSM SecureString PEM path: with this key wired, no copy of the signing
# private key exists outside KMS (the same no-external-copies condition the erasure story relies
# on for data keys, applied to the proof signer).

resource "aws_kms_key" "proof_signing" {
  description              = "${local.name} erasure-proof signing key (ECDSA P-256; private key never leaves KMS)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  tags = {
    project = "erasure-proof"
  }
}

resource "aws_kms_alias" "proof_signing" {
  name          = "alias/${local.name}-proof-signing"
  target_key_id = aws_kms_key.proof_signing.key_id
}
