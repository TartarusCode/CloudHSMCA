###############################################################################
# Outputs — the whole PKI, from one apply
###############################################################################

###############################################################################
# Ceremony
###############################################################################

output "state_machine_arn" {
  description = "Run the ceremony with `aws stepfunctions start-execution`."
  value       = aws_sfn_state_machine.ceremony.arn
}

output "start_bootstrap_command" {
  description = "Start a bootstrap ceremony (the cluster must be UNINITIALIZED). Prints the execution ARN."
  value = join(" ", [
    "aws stepfunctions start-execution",
    "--state-machine-arn", aws_sfn_state_machine.ceremony.arn,
    "--name", "bootstrap-$(date -u +%Y%m%dT%H%M%SZ)",
    "--input", jsonencode({ mode = "BOOTSTRAP" }),
    "--query", "executionArn", "--output", "text",
  ])
}

output "start_rotation_command" {
  description = "Start an Intermediate CA rotation (needs a READY cluster backup)."
  value = join(" ", [
    "aws stepfunctions start-execution",
    "--state-machine-arn", aws_sfn_state_machine.ceremony.arn,
    "--name", "rotate-$(date -u +%Y%m%dT%H%M%SZ)",
    "--input", jsonencode({ mode = "ROTATE_INTERMEDIATE" }),
    "--query", "executionArn", "--output", "text",
  ])
}

output "cloudhsm_cluster_id" {
  description = "Durable cluster shell. Its backups escrow the Root CA key."
  value       = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "execution_history_log_group" {
  description = "Every ceremony execution is logged here, with full execution data."
  value       = aws_cloudwatch_log_group.ceremony.name
}

###############################################################################
# Key material and the published chain
###############################################################################

output "intermediate_kms_key_arn" {
  description = "The Intermediate CA key: signs workload certificates and CRLs, never exportable."
  value       = aws_kms_key.intermediate_ca.arn
}

output "intermediate_kms_key_alias" {
  description = "Alias of the Intermediate CA key."
  value       = aws_kms_alias.intermediate_ca.name
}

output "certificate_parameters" {
  description = "SSM Parameter Store paths the ceremony publishes and the Lambda reads."
  value = {
    root_ca_pem         = local.ssm_root_ca_pem
    intermediate_ca_pem = local.ssm_intermediate_ca_pem
    ca_bundle_pem       = local.ssm_ca_bundle_pem
    ceremony_state      = local.ssm_ceremony_state
  }
}

output "artifact_bucket" {
  description = "Bucket holding the tooling, issued certificates, CRLs and revocation input."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_prefixes" {
  description = "Where the Lambda and operators read and write CRL artifacts."
  value = {
    crl         = "s3://${aws_s3_bucket.artifacts.id}/crl/"
    revocations = "s3://${aws_s3_bucket.artifacts.id}/${var.revocations_s3_key}"
  }
}

###############################################################################
# Roles Anywhere
###############################################################################

output "trust_anchor_arn" {
  description = "Trust anchor ARN. It is created DISABLED with a placeholder bundle and activated by the ceremony."
  value       = aws_rolesanywhere_trust_anchor.this.arn
}

output "trust_anchor_id" {
  description = "Trust anchor id (the ceremony's UpdateTrustAnchor/EnableTrustAnchor states use it)."
  value       = aws_rolesanywhere_trust_anchor.this.id
}

output "profile_arns" {
  description = "Map of workload key -> Roles Anywhere profile ARN."
  value       = { for key, profile in aws_rolesanywhere_profile.this : key => profile.arn }
}

output "workload_role_arns" {
  description = "Map of workload key -> IAM role ARN assumable through Roles Anywhere."
  value       = { for key, role in aws_iam_role.workload : key => role.arn }
}

output "rolesanywhere_update_env" {
  description = "Values for aws_signing_helper: no long-lived credentials, just the ARNs."
  value = {
    trust_anchor_arn = aws_rolesanywhere_trust_anchor.this.arn
    region           = local.region
    example_command = try(join(" ", [
      "aws_signing_helper credential-process",
      "--certificate /etc/pki/workload.pem",
      "--private-key /etc/pki/workload.key",
      "--trust-anchor-arn", aws_rolesanywhere_trust_anchor.this.arn,
      "--profile-arn", values(aws_rolesanywhere_profile.this)[0].arn,
      "--role-arn", values(aws_iam_role.workload)[0].arn,
    ]), null)
  }
}

###############################################################################
# CRL
###############################################################################

output "crl_issuer_function_name" {
  description = "CRL refresh Lambda (invoke manually with `aws lambda invoke --payload '{\"reason\":\"manual\"}'`)."
  value       = aws_lambda_function.crl_issuer.function_name
}

output "crl_issuer_role_arn" {
  description = "Role that signs CRLs (the Intermediate key policy allows it under aws:PrincipalArn)."
  value       = aws_iam_role.crl_issuer.arn
}

output "cloudhsm_backup_guard_policy_arn" {
  description = "Attach this policy to every principal, beyond the two here, that can manage CloudHSM (it denies backup deletion)."
  value       = aws_iam_policy.cloudhsm_backup_guard.arn
}
