###############################################################################
# IAM Roles Anywhere
#
#   trust anchor  created DISABLED with a placeholder bundle, activated by the
#                 ceremony (see ceremony.tf and statemachine.asl.json.tftpl)
#   profiles      one per var.workload_profiles entry
#   roles         assumption restricted to rolesanywhere.amazonaws.com, this
#                 trust anchor (aws:SourceArn) and, optionally, the x509 subject
#                 fields Roles Anywhere puts in the session principal tags
#
# Why the placeholder exists
# --------------------------
# CreateTrustAnchor needs a certificate bundle, but the real chain only exists
# after a ceremony that itself needs the cluster, the KMS key and this anchor to
# exist first. Creating the anchor enabled with the real chain therefore forced a
# second apply, gated on an SSM parameter that would not exist yet.
#
# Instead the anchor is created DISABLED with a throwaway self-signed certificate,
# and the workflow installs the real bundle (UpdateTrustAnchor) and enables it
# (EnableTrustAnchor). `ignore_changes = [source, enabled]` is what makes that
# safe: no later plan can revert the chain or disable a working anchor.
#
# The placeholder key never signs anything and lives only in Terraform state
# (it cannot be marked ephemeral: `ephemeral` blocks need Terraform 1.10, and this
# module supports 1.6+). It is destroyed with the state.
#
# CRL
# ---
# hashicorp/aws has no aws_rolesanywhere_crl resource (the 5.100.0 and 6.73.0
# schemas were both checked), so nothing here holds CRL state: the CRL Lambda and
# the ceremony's ImportOrUpdateCrl state import it through rolesanywhere:ImportCrl.
###############################################################################

resource "tls_private_key" "placeholder" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_self_signed_cert" "placeholder" {
  private_key_pem = tls_private_key.placeholder.private_key_pem

  is_ca_certificate     = true
  validity_period_hours = 1
  allowed_uses          = ["cert_signing", "crl_signing"]

  subject {
    common_name  = "${var.name} placeholder — not a certificate authority"
    organization = "placeholder"
  }
}

resource "aws_rolesanywhere_trust_anchor" "this" {
  name    = "${var.name}-trust-anchor"
  enabled = false # the ceremony flips this on once the real chain is installed
  tags    = local.tags

  source {
    source_type = "CERTIFICATE_BUNDLE"

    source_data {
      # Replaced by the ceremony with Root + Intermediate from the HSM and KMS
      # CAs. KMS validates this one as a well-formed CA certificate and nothing
      # else; no workload can authenticate against it.
      x509_certificate_data = tls_self_signed_cert.placeholder.cert_pem
    }
  }

  lifecycle {
    # The ceremony owns both fields from here on. Without this, every plan would
    # try to restore the placeholder and disable the anchor.
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

  name                 = "${var.name}-${each.key}"
  description          = each.value.description
  assume_role_policy   = data.aws_iam_policy_document.workload_assume[each.key].json
  max_session_duration = each.value.session_duration_seconds
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

  name                        = "${var.name}-${each.key}"
  enabled                     = true
  role_arns                   = [aws_iam_role.workload[each.key].arn]
  managed_policy_arns         = each.value.managed_policy_arns
  duration_seconds            = each.value.session_duration_seconds
  accept_role_session_name    = each.value.accept_role_session_name
  require_instance_properties = false
  session_policy              = each.value.session_policy_json
  tags                        = merge(local.tags, each.value.tags)
}
