###############################################################################
# The trust store, bootstrapped with a placeholder bundle
#
# elbv2:CreateTrustStore needs a PEM CA bundle in S3 at creation time, but the
# real chain only exists after a ceremony. So a throwaway self-signed certificate
# is uploaded first, the trust store is created against that object version, and
# the sync Lambda overwrites both when CAChainPublished arrives.
#
# ignore_changes on the object is what makes the overwrite stick: without it every
# plan would restore the placeholder; ignore_changes on the trust store's object
# version is what stops Terraform reverting the Lambda's ModifyTrustStore.
###############################################################################

locals {
  name   = var.name != "" ? var.name : var.ca_contract.name
  prefix = "alb-mtls/${local.name}"
}

resource "tls_private_key" "placeholder" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_self_signed_cert" "placeholder" {
  private_key_pem = tls_private_key.placeholder.private_key_pem

  is_ca_certificate = true
  allowed_uses      = ["cert_signing", "crl_signing"]

  # One year: nothing validates against this certificate while the trust store has
  # no listeners attached, but an expired bundle is rejected by CreateTrustStore,
  # and a delayed apply must not spend a short window.
  validity_period_hours = 8760

  subject {
    common_name  = "${local.name} ALB mTLS placeholder — not a certificate authority"
    organization = "placeholder"
  }
}

resource "aws_s3_object" "placeholder_bundle" {
  bucket        = var.ca_contract.artifacts_bucket
  key           = local.bundle_key
  content       = tls_self_signed_cert.placeholder.cert_pem
  content_type  = "application/x-pem-file"
  tags          = local.tags
  force_destroy = false

  server_side_encryption = "AES256"

  lifecycle {
    # The Lambda owns this object once the CA publishes its chain. version_id is
    # not listed: it is provider-computed, so there is no configured value for
    # Terraform to compare against and listing it only earns a warning.
    ignore_changes = [content, etag]
  }
}

resource "aws_lb_trust_store" "this" {
  name = local.trust_store_name

  ca_certificates_bundle_s3_bucket         = aws_s3_object.placeholder_bundle.bucket
  ca_certificates_bundle_s3_key            = aws_s3_object.placeholder_bundle.key
  ca_certificates_bundle_s3_object_version = aws_s3_object.placeholder_bundle.version_id

  tags = local.tags

  lifecycle {
    # The Lambda rotates the bundle by calling ModifyTrustStore; Terraform must not
    # drag it back to the placeholder version.
    ignore_changes = [ca_certificates_bundle_s3_object_version]

    precondition {
      condition     = length(local.trust_store_name) <= 32
      error_message = "ELBv2 caps a trust store name at 32 characters: \"${local.trust_store_name}\" is ${length(local.trust_store_name)}. Shorten var.name or set var.trust_store_name."
    }
  }
}
