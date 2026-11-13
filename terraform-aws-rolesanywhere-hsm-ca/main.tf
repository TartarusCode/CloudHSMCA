###############################################################################
# Always-online foundation for terraform-aws-rolesanywhere-hsm-ca
#
#  * aws_kms_key            — Intermediate CA private key (SIGN_VERIFY, FIPS 140-3
#                             Level 3 HSM backed, never exportable)
#  * aws_s3_bucket          — certificate + CRL artifacts, versioned and
#                             Object-Lock protected
#  * aws_ssm_parameter      — the certificate chain the two phases hand over
#                             through, plus the ceremony bootstrap secrets
#  * aws_iam_policy         — deny-list that keeps the CloudHSM backup which
#                             holds the offline Root CA key from being purged
#
# Cost note: everything here is ~$1/mo (one asymmetric KMS key) plus S3 storage
# of a few kilobytes. There is no ACM Private CA, no always-on HSM.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  # Phase 2 = steady state. Everything ceremony-only is gated on this.
  phase2 = !var.ceremony_mode

  tags = merge(var.tags, {
    Module   = "terraform-aws-rolesanywhere-hsm-ca"
    Phase    = var.ceremony_mode ? "ceremony" : "steady-state"
    Workload = var.name
  })

  # SSM hand-over contract between phase 1 (ceremony host writes) and
  # phase 2 (trust anchor reads). Terraform creates these with a sentinel so
  # both phases see the same paths, and never overwrites the ceremony output.
  ssm_prefix                = "/${var.name}/pki"
  ssm_root_ca_pem           = "${local.ssm_prefix}/root_ca.pem"
  ssm_intermediate_ca_pem   = "${local.ssm_prefix}/intermediate_ca.pem"
  ssm_ca_bundle_pem         = "${local.ssm_prefix}/ca_bundle.pem"
  ssm_ceremony_state        = "${local.ssm_prefix}/ceremony/state"
  ssm_hsm_admin_password    = "${local.ssm_prefix}/ceremony/hsm-admin-password"
  ssm_hsm_cu_password       = "${local.ssm_prefix}/ceremony/hsm-cu-password"
  ceremony_pending_sentinel = "PENDING-CEREMONY"

  # The Intermediate CA key may only ever produce ECDSA signatures over a
  # digest with the one algorithm that matches its key spec.
  ca_signing_algorithm = {
    ECC_NIST_P256 = "ECDSA_SHA_256"
    ECC_NIST_P384 = "ECDSA_SHA_384"
    ECC_NIST_P521 = "ECDSA_SHA_512"
  }[var.intermediate_key_spec]

  # Principals that may use the CA key. The CRL issuer always needs it; the
  # ceremony host needs GetPublicKey + Sign to build the intermediate CSR.
  ca_key_principals = concat(
    var.ceremony_mode ? [aws_iam_role.ceremony_host[0].arn] : [],
    [aws_iam_role.crl_issuer.arn],
    var.intermediate_signer_principal_arns,
  )
}

###############################################################################
# Intermediate CA key (KMS asymmetric, never exportable)
###############################################################################

data "aws_iam_policy_document" "intermediate_ca_key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # Signing is restricted to raw-digest requests with the single algorithm that
  # matches the key spec, so this key cannot be repurposed as a general signer.
  statement {
    sid       = "CaSignDigestOnly"
    actions   = ["kms:Sign"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.ca_key_principals
    }

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = [local.ca_signing_algorithm]
    }
  }

  # Read/metadata actions are a separate statement on purpose: the condition
  # keys above do not exist on GetPublicKey, so folding them together would
  # deny every non-signing call.
  statement {
    sid       = "CaPublicKeyRead"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.ca_key_principals
    }
  }
}

resource "aws_kms_key" "intermediate_ca" {
  description = "${var.name} IAM Roles Anywhere Intermediate CA (${var.intermediate_key_spec})"
  key_usage   = "SIGN_VERIFY"
  # `key_spec` exists in aws 5.x but was removed again in 6.x (verified against
  # both provider schemas); `customer_master_key_spec` is accepted by both.
  customer_master_key_spec = var.intermediate_key_spec
  policy                   = data.aws_iam_policy_document.intermediate_ca_key.json
  deletion_window_in_days  = var.kms_deletion_window_in_days
  enable_key_rotation      = false # asymmetric KMS keys cannot be rotated
  multi_region             = false
  tags                     = local.tags
}

resource "aws_kms_alias" "intermediate_ca" {
  name          = "alias/${var.name}-intermediate-ca"
  target_key_id = aws_kms_key.intermediate_ca.key_id
}

###############################################################################
# Artifact bucket (certificates, CRLs, rewards for auditors)
###############################################################################

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix       = var.artifact_bucket_name == "" ? "${var.name}-pki-" : null
  bucket              = var.artifact_bucket_name != "" ? var.artifact_bucket_name : null
  object_lock_enabled = true
  force_destroy       = false
  tags                = local.tags
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }

  # Object Lock can only be configured once versioning is enabled.
  depends_on = [aws_s3_bucket_versioning.artifacts]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3, not the CA key: losing the CA key must never make the audit
      # artifacts unreadable (and an asymmetric key could not encrypt anyway).
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "artifacts_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

###############################################################################
# SSM hand-over parameters
###############################################################################

resource "random_password" "hsm_admin" {
  count   = var.ceremony_mode ? 1 : 0
  length  = 32
  special = true
  # CloudHSM accepts any printable ASCII; keep to a shell-safe subset because
  # the value is passed to cloudhsm-cli over an SSM session.
  override_special = "_-+=:."
}

resource "random_password" "hsm_cu" {
  count            = var.ceremony_mode ? 1 : 0
  length           = 32
  special          = true
  override_special = "_-+=:."
}

resource "aws_ssm_parameter" "hsm_admin_password" {
  count       = var.ceremony_mode ? 1 : 0
  name        = local.ssm_hsm_admin_password
  description = "Bootstrap password of the unactivated CloudHSM admin user"
  type        = "SecureString"
  value       = random_password.hsm_admin[0].result
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "hsm_cu_password" {
  count       = var.ceremony_mode ? 1 : 0
  name        = local.ssm_hsm_cu_password
  description = "Password of the CloudHSM crypto user that owns the Root key"
  type        = "SecureString"
  value       = random_password.hsm_cu[0].result
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "root_ca_pem" {
  name        = local.ssm_root_ca_pem
  description = "Offline Root CA certificate (public key material only)"
  type        = "String"
  value       = var.ceremony_mode ? local.ceremony_pending_sentinel : ""
  tags        = local.tags

  lifecycle {
    # The ceremony host writes the real certificate during phase 1; Terraform
    # must never revert it to the sentinel on a later apply.
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "intermediate_ca_pem" {
  name        = local.ssm_intermediate_ca_pem
  description = "KMS Intermediate CA certificate"
  type        = "String"
  value       = var.ceremony_mode ? local.ceremony_pending_sentinel : ""
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ca_bundle_pem" {
  name        = local.ssm_ca_bundle_pem
  description = "Roles Anywhere CERTIFICATE_BUNDLE: Root CA followed by Intermediate CA"
  type        = "String"
  value       = var.ceremony_mode ? local.ceremony_pending_sentinel : ""
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ceremony_state" {
  name        = local.ssm_ceremony_state
  description = "Progress marker written by the ceremony host (scripts/hsm_ceremony.sh)"
  type        = "String"
  value       = var.ceremony_mode ? "NOT_STARTED" : "COMPLETE"
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

###############################################################################
# CloudHSM backup protection
#
# The offline Root CA private key exists in exactly one place after phase 2:
# the automatic, encrypted cluster backup. Deleting that backup would destroy
# the ability to issue a new Intermediate CA without a full key ceremony, so
# the deny is unconditional and account-wide (backup IDs are not known at plan
# time, and a scoped resource would be trivially bypassed by a new backup).
###############################################################################

data "aws_iam_policy_document" "cloudhsm_backup_guard" {
  statement {
    sid    = "DenyCloudHsmBackupDeletion"
    effect = "Deny"
    actions = [
      "cloudhsm:DeleteBackup",
      "cloudhsm:ModifyBackupAttributes",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cloudhsm_backup_guard" {
  name        = "${var.name}-deny-cloudhsm-backup-deletion"
  description = "Denies deletion or attribute changes of AWS CloudHSM backups (offline Root CA key escrow)"
  policy      = data.aws_iam_policy_document.cloudhsm_backup_guard.json
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "ceremony_backup_guard" {
  count      = var.ceremony_mode ? 1 : 0
  role       = aws_iam_role.ceremony_host[0].name
  policy_arn = aws_iam_policy.cloudhsm_backup_guard.arn
}

data "aws_iam_role" "extra_backup_guard_roles" {
  for_each = toset(var.backup_guard_role_names)
  name     = each.value
}

resource "aws_iam_role_policy_attachment" "extra_backup_guard" {
  for_each   = data.aws_iam_role.extra_backup_guard_roles
  role       = each.value.name
  policy_arn = aws_iam_policy.cloudhsm_backup_guard.arn
}
