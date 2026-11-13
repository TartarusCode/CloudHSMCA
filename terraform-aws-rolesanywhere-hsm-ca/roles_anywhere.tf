###############################################################################
# Phase 2 — IAM Roles Anywhere
#
#   trust anchor  CERTIFICATE_BUNDLE (Root CA + Intermediate CA, from SSM)
#   profiles      one per var.workload_profiles entry
#   roles         assumption restricted to rolesanywhere.amazonaws.com, this
#                 trust anchor (aws:SourceArn) and, optionally, the x509 subject
#                 fields Roles Anywhere puts in the session principal tags
#
# CRL note — important
# --------------------
# hashicorp/aws has NO `aws_rolesanywhere_crl` resource: the verified provider
# schemas for both 5.100.0 and 6.73.0 expose only aws_rolesanywhere_profile and
# aws_rolesanywhere_trust_anchor, and a resource block for a non-existent type
# fails validation. CRLs are therefore created through the Roles Anywhere
# ImportCrl API, which is exactly what the Lambda in crl_issuer_lambda.tf does
# (raw DER bytes, no PEM/base64 ambiguity). The one-shot `terraform_data`
# below runs the same Lambda at apply time so a CRL exists before the first
# certificate is presented; every subsequent refresh is the daily schedule.
###############################################################################

locals {
  # Empty in ceremony mode: nothing Roles Anywhere-shaped exists until the
  # certificate chain has been produced by the HSM ceremony.
  workload_profiles = var.ceremony_mode ? {} : var.workload_profiles

  trust_anchor_bundle = local.phase2 ? data.aws_ssm_parameter.ca_bundle[0].value : ""
}

data "aws_ssm_parameter" "ca_bundle" {
  count = local.phase2 ? 1 : 0
  name  = local.ssm_ca_bundle_pem
}

data "aws_ssm_parameter" "intermediate_ca_pem" {
  count = local.phase2 ? 1 : 0
  name  = local.ssm_intermediate_ca_pem
}

resource "aws_rolesanywhere_trust_anchor" "this" {
  count = local.phase2 ? 1 : 0

  name    = "${var.name}-trust-anchor"
  enabled = true
  tags    = local.tags

  source {
    source_type = "CERTIFICATE_BUNDLE"

    source_data {
      # Root first, then Intermediate: both must be present so that a CRL
      # issued by either CA is accepted.
      x509_certificate_data = local.trust_anchor_bundle
    }
  }

  lifecycle {
    precondition {
      condition = (
        can(regex("-----BEGIN CERTIFICATE-----", local.trust_anchor_bundle)) &&
        length(regexall("-----BEGIN CERTIFICATE-----", local.trust_anchor_bundle)) >= 2 &&
        !can(regex("PENDING-CEREMONY", local.trust_anchor_bundle))
      )
      error_message = <<-EOT
        The CA bundle at ${local.ssm_ca_bundle_pem} does not contain a usable
        Root + Intermediate chain. Run the ceremony with ceremony_mode = true
        first, and confirm the ceremony SSM parameter reports COMPLETE.
      EOT
    }
  }
}

###############################################################################
# Workload IAM roles
###############################################################################

data "aws_iam_policy_document" "workload_assume" {
  for_each = local.workload_profiles

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
      values   = [aws_rolesanywhere_trust_anchor.this[0].arn]
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
  for_each = local.workload_profiles

  name                 = "${var.name}-${each.key}"
  description          = each.value.description
  assume_role_policy   = data.aws_iam_policy_document.workload_assume[each.key].json
  max_session_duration = each.value.session_duration_seconds
  tags                 = merge(local.tags, each.value.tags, { Workload = each.key })
}

locals {
  workload_policy_attachments = merge([
    for profile_key, profile in local.workload_profiles : {
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
  for_each = local.workload_profiles

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

###############################################################################
# One-shot CRL bootstrap
#
# Purely so that the first `aws_s3` / API call from a workload does not fail on
# "no CRL in trust anchor". Idempotent by trigger: it re-runs only when
# var.crl_bootstrap_generation is bumped or the trust anchor is replaced.
###############################################################################

resource "terraform_data" "bootstrap_crl" {
  count = local.phase2 && var.auto_bootstrap_crl ? 1 : 0

  triggers_replace = [
    var.crl_bootstrap_generation,
    aws_rolesanywhere_trust_anchor.this[0].id,
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      FUNCTION_NAME = aws_lambda_function.crl_issuer.function_name
      AWS_REGION    = local.region
    }
    command = <<-EOT
      set -euo pipefail
      out=$(mktemp)
      trap 'rm -f "$out"' EXIT
      aws lambda invoke \
        --function-name "$FUNCTION_NAME" \
        --cli-binary-format raw-in-base64-out \
        --payload '{"reason":"terraform-bootstrap"}' \
        --region "$AWS_REGION" "$out"
      echo "--- CRL lambda response ---"
      cat "$out"
      grep -q '"ok": *true' "$out" || {
        echo "CRL bootstrap failed: the Lambda did not report ok=true" >&2
        exit 1
      }
    EOT
  }

  depends_on = [
    aws_rolesanywhere_trust_anchor.this,
    aws_lambda_function.crl_issuer,
  ]
}
