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
# aws_rolesanywhere_trust_anchor. The CRL resource lives in the **AWSCC**
# provider (`awscc_rolesanywhere_crl`), which wraps AWS::RolesAnywhere::CRL.
#
# Exactly one actor owns the CRL object; two overlapping owners leave an enabled
# CRL whose nextUpdate expires while a newer one also exists:
#
#   crl_management_mode = "awscc"  (default)
#     awscc_rolesanywhere_crl manages it from var.crl_pem_path. ImportCrl takes
#     PEM ("a CRL must be in PEM format"), which is why CrlData is a CFN String
#     and why this module feeds it a PEM file rather than raw DER.
#     Rotation = regenerate crl.pem + `terraform apply` (CI job).
#
#   crl_management_mode = "lambda"
#     The scheduled Lambda imports a fresh CRL every 24 hours through
#     rolesanywhere:ImportCrl; Terraform keeps no CRL state. The Lambda refuses
#     to run when awscc owns the CRL, so a stray invoke cannot fork the object.
###############################################################################

locals {
  # Empty in ceremony mode: nothing Roles Anywhere-shaped exists until the
  # certificate chain has been produced by the HSM ceremony.
  workload_profiles = var.ceremony_mode ? {} : var.workload_profiles

  trust_anchor_bundle = local.phase2 ? data.aws_ssm_parameter.ca_bundle[0].value : ""

  crl_owned_by_awscc = local.phase2 && var.crl_management_mode == "awscc"

  crl_pem = local.crl_owned_by_awscc && var.crl_pem_path != "" && fileexists(var.crl_pem_path) ? file(var.crl_pem_path) : ""
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
# CRL object — declarative (awscc)
###############################################################################

resource "awscc_rolesanywhere_crl" "this" {
  count = local.crl_owned_by_awscc ? 1 : 0

  name             = "${var.name}-crl"
  trust_anchor_arn = aws_rolesanywhere_trust_anchor.this[0].arn
  enabled          = true
  crl_data         = trimspace(local.crl_pem)

  depends_on = [aws_rolesanywhere_trust_anchor.this]

  lifecycle {
    precondition {
      condition     = can(regex("-----BEGIN X509 CRL-----", local.crl_pem))
      error_message = <<-EOT
        crl_management_mode is "awscc" but no PEM CRL was supplied
        (var.crl_pem_path = "${var.crl_pem_path}"). Roles Anywhere accepts a CRL
        only in PEM format and Terraform cannot sign one, so produce it first:

          python3 scripts/kms_ca_tool.py generate-crl --signer kms \
            --kms-key-id ${aws_kms_key.intermediate_ca.arn} \
            --issuer-cert intermediate_ca.pem \
            --revoked-file revoked.json --out crl.pem

        or set crl_management_mode = "lambda" to let the scheduled Lambda own it.
      EOT
    }
  }
}

###############################################################################
# CRL object — scheduled import (lambda)
#
# One-shot bootstrap so the first request from a workload does not fail on
# "no CRL in trust anchor". Idempotent by trigger: it re-runs only when
# var.crl_bootstrap_generation is bumped or the trust anchor is replaced.
###############################################################################

resource "terraform_data" "bootstrap_crl" {
  count = local.phase2 && var.crl_management_mode == "lambda" && var.auto_bootstrap_crl ? 1 : 0

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
