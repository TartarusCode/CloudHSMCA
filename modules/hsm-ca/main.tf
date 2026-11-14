###############################################################################
# The durable foundation
#
# Everything the PKI needs that outlives a ceremony, in the same module as the
# ceremony and the Roles Anywhere runtime — one apply, no cross-stack hand-over:
#
#  * aws_s3_bucket           tooling, issued certificates, CRLs and revocation
#                            input. Versioned, Object-Locked, TLS-only.
#  * aws_iam_policy          deny-list protecting the CloudHSM backup that
#                            escrows the offline Root CA private key
#
# The cluster shell, KMS Intermediate key and state machine live in ceremony.tf;
# the trust anchor and workload roles in roles_anywhere.tf; the CRL machinery in
# crl_issuer_lambda.tf. Shared locals are declared once, in ceremony.tf.
###############################################################################

###############################################################################
# Artifact bucket
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
      # artifacts or the published chain unreadable, and an asymmetric key could
      # not encrypt anyway.
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
# is unconditional and account-wide — backup ids do not exist at plan time, and a
# scoped resource would be bypassed by any new backup.
#
# The two principals in this module that can manage CloudHSM are attached here by
# resource reference. Anyone else who can must attach it themselves; the policy
# ARN is an output.
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

resource "aws_iam_role_policy_attachment" "cloudhsm_backup_guard" {
  for_each = {
    ceremony_host = aws_iam_role.ceremony_host.name
    state_machine = aws_iam_role.sfn.name
  }

  role       = each.value
  policy_arn = aws_iam_policy.cloudhsm_backup_guard.arn
}
