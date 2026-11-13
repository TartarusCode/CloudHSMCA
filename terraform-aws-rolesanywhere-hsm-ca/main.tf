###############################################################################
# Runtime foundation for terraform-aws-rolesanywhere-hsm-ca
#
# This module CONSUMES a certificate chain; it never creates one. The Root CA
# ceremony is ceremony/ (a Step Functions workflow with a CloudHSM), which
# publishes /<name>/pki/*.pem to SSM Parameter Store and creates the KMS
# Intermediate CA key. Nothing here waits for an earlier phase of itself, so a
# single apply produces a complete runtime.
#
#  * data aws_ssm_parameter  the published chain (Root + Intermediate)
#  * aws_s3_bucket           CRLs and revocation input, versioned, Object-Locked
#  * aws_iam_policy          deny-list protecting the CloudHSM backup that
#                            escrows the offline Root CA key
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge(var.tags, {
    Module   = "terraform-aws-rolesanywhere-hsm-ca"
    Workload = var.name
  })

  # The hand-over contract with ceremony/: fixed paths, published by the
  # workflow, read here. Both stacks derive them from the same `name`.
  ssm_prefix              = "/${var.name}/pki"
  ssm_root_ca_pem         = "${local.ssm_prefix}/root_ca.pem"
  ssm_intermediate_ca_pem = "${local.ssm_prefix}/intermediate_ca.pem"
  ssm_ca_bundle_pem       = "${local.ssm_prefix}/ca_bundle.pem"
  ssm_ceremony_state      = "${local.ssm_prefix}/ceremony/state"
}

###############################################################################
# Artifact bucket (CRLs, revocation input, audit copies)
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
      # SSE-S3, not the CA key: losing that key must never make the audit
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
# CloudHSM backup protection
#
# The offline Root CA private key exists in exactly one place after a ceremony:
# the automatic, encrypted cluster backup. Deleting that backup destroys the
# ability to issue a new Intermediate CA without a new key ceremony, so the deny
# is unconditional and account-wide (backup IDs do not exist at plan time, and a
# scoped resource would be bypassed by any new backup).
#
# The cluster itself belongs to ceremony/; this policy protects it from the
# credentials that merely manage the account.
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

data "aws_iam_role" "extra_backup_guard_roles" {
  for_each = toset(var.backup_guard_role_names)
  name     = each.value
}

resource "aws_iam_role_policy_attachment" "extra_backup_guard" {
  for_each   = data.aws_iam_role.extra_backup_guard_roles
  role       = each.value.name
  policy_arn = aws_iam_policy.cloudhsm_backup_guard.arn
}
