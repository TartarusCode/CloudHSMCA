###############################################################################
# IAM Roles Anywhere — the consumer
#
#   trust anchor  created DISABLED with a placeholder bundle; activated by the
#                 CRL Lambda when the CA publishes its chain
#   profiles      one per var.workload_profiles entry
#   roles         assumption restricted to rolesanywhere.amazonaws.com, this
#                 trust anchor (aws:SourceArn) and, optionally, the x509 subject
#                 fields Roles Anywhere puts in the session principal tags
#
# This module never touches CloudHSM or the ceremony. It subscribes to
# cloudhsmca.pki/CAChainPublished (see crl_issuer_lambda.tf), and every ARN or
# parameter name it needs comes from var.ca_contract.
#
# Why the placeholder exists
# --------------------------
# CreateTrustAnchor needs a certificate bundle, but the real chain only exists
# after a ceremony that itself needs the cluster and the KMS key to exist first.
# Waiting for the chain made the first apply a two-pass affair. Instead the anchor
# is created DISABLED with a throwaway self-signed certificate, and the activation
# Lambda installs the real bundle (UpdateTrustAnchor) and enables it
# (EnableTrustAnchor). `ignore_changes = [source, enabled]` is what makes that
# safe: no later plan can revert the chain or disable a working anchor.
#
# The placeholder key never signs anything and lives only in Terraform state (it
# cannot be marked ephemeral: `ephemeral` blocks need Terraform 1.10, and this
# module supports 1.6+). It is destroyed with the state.
#
# CRL
# ---
# hashicorp/aws has no aws_rolesanywhere_crl resource (the 5.100.0 and 6.73.0
# schemas were both checked), so nothing here holds CRL state: the Lambda imports
# it through rolesanywhere:ImportCrl on activation and on the 24-hour schedule.
###############################################################################

locals {
  name       = var.ca_contract.name
  module_tag = "cloudhsmca"

  tags = merge(var.tags, {
    Module = local.module_tag
    Ca     = local.name
  })

  ca_bundle_param_arn = "arn:${var.ca_contract.partition}:ssm:${var.ca_contract.region}:${var.ca_contract.account_id}:parameter${var.ca_contract.ca_bundle_ssm_param}"
  issuer_param_arn    = "arn:${var.ca_contract.partition}:ssm:${var.ca_contract.region}:${var.ca_contract.account_id}:parameter${var.ca_contract.intermediate_ca_ssm_param}"
}

resource "tls_private_key" "placeholder" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_self_signed_cert" "placeholder" {
  private_key_pem = tls_private_key.placeholder.private_key_pem

  is_ca_certificate = true
  allowed_uses      = ["cert_signing", "crl_signing"]

  # A year, not an hour. Nothing signs with this key and the anchor is created
  # DISABLED, so its expiry has no security meaning — but a 1-hour certificate
  # would be expired by the time AWS validates it during a delayed apply or on a
  # host whose clock is skewed, and CreateTrustAnchor rejects an expired bundle.
  validity_period_hours = 8760

  subject {
    common_name  = "${local.name} placeholder — not a certificate authority"
    organization = "placeholder"
  }
}

resource "aws_rolesanywhere_trust_anchor" "this" {
  name    = "${local.name}-trust-anchor"
  enabled = false # the activation Lambda flips this on when the chain arrives
  tags    = local.tags

  source {
    source_type = "CERTIFICATE_BUNDLE"

    source_data {
      # Replaced with Root + Intermediate as soon as the ceremony publishes them.
      # Roles Anywhere validates this one as a well-formed CA certificate and
      # nothing else; no workload can authenticate against it.
      x509_certificate_data = tls_self_signed_cert.placeholder.cert_pem
    }
  }

  lifecycle {
    # The Lambda owns both fields from here on. Without this, every plan would try
    # to restore the placeholder and disable the anchor.
    ignore_changes = [source, enabled]
  }
}

###############################################################################
# Workload IAM roles
###############################################################################

data "aws_iam_policy_document" "workload_assume" {
  for_each = var.workload_profiles

  statement {
    sid = "RolesAnywhereAssumeRole"
    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
      "sts:SetSourceIdentity",
    ]

    principals {
      type        = "Service"
      identifiers = ["rolesanywhere.amazonaws.com"]
    }

    # Hard requirement: only this module's trust anchor may mint sessions.
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_rolesanywhere_trust_anchor.this.arn]
    }

    # Optional second lock: the certificate subject must carry the expected
    # OU / CN, which Roles Anywhere projects as session principal tags.
    dynamic "condition" {
      for_each = {
        for key, value in {
          OU = each.value.allowed_subject_ou
          CN = each.value.allowed_subject_cn
        } : key => value if value != null
      }

      content {
        test     = each.value.subject_condition_operator
        variable = "aws:PrincipalTag/x509Subject/${condition.key}"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role" "workload" {
  for_each = var.workload_profiles

  name                 = "${local.name}-${each.key}"
  description          = each.value.description
  assume_role_policy   = data.aws_iam_policy_document.workload_assume[each.key].json
  max_session_duration = coalesce(each.value.role_max_session_duration, max(3600, each.value.session_duration_seconds))
  permissions_boundary = var.permissions_boundary_arn
  tags                 = merge(local.tags, each.value.tags, { Workload = each.key })
}

locals {
  workload_policy_attachments = merge([
    for profile_key, profile in var.workload_profiles : {
      for arn in profile.managed_policy_arns : "${profile_key}|${arn}" => {
        profile = profile_key
        arn     = arn
      }
    }
  ]...)
}

resource "aws_iam_role_policy_attachment" "workload" {
  for_each = local.workload_policy_attachments

  role       = aws_iam_role.workload[each.value.profile].name
  policy_arn = each.value.arn
}

###############################################################################
# Roles Anywhere profiles
###############################################################################

resource "aws_rolesanywhere_profile" "this" {
  for_each = var.workload_profiles

  name                        = "${local.name}-${each.key}"
  enabled                     = true
  role_arns                   = [aws_iam_role.workload[each.key].arn]
  managed_policy_arns         = each.value.managed_policy_arns
  duration_seconds            = each.value.session_duration_seconds
  accept_role_session_name    = each.value.accept_role_session_name
  require_instance_properties = false
  session_policy              = each.value.session_policy_json
  tags                        = merge(local.tags, each.value.tags)
}
