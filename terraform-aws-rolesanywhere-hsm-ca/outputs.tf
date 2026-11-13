###############################################################################
# Outputs
###############################################################################

output "trust_anchor_arn" {
  description = "IAM Roles Anywhere trust anchor ARN."
  value       = aws_rolesanywhere_trust_anchor.this.arn
}

output "profile_arns" {
  description = "Map of workload key -> Roles Anywhere profile ARN."
  value       = { for key, profile in aws_rolesanywhere_profile.this : key => profile.arn }
}

output "workload_role_arns" {
  description = "Map of workload key -> IAM role ARN assumable through Roles Anywhere."
  value       = { for key, role in aws_iam_role.workload : key => role.arn }
}

output "certificate_parameters" {
  description = "The SSM parameters this module reads (published by ceremony/)."
  value = {
    root_ca_pem         = local.ssm_root_ca_pem
    intermediate_ca_pem = local.ssm_intermediate_ca_pem
    ca_bundle_pem       = local.ssm_ca_bundle_pem
    ceremony_state      = local.ssm_ceremony_state
  }
}

output "artifact_bucket" {
  description = "S3 bucket holding CRLs, revocation input and audit copies."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_prefixes" {
  description = "Where the Lambda and operators read and write CRL artifacts."
  value = {
    crl         = "s3://${aws_s3_bucket.artifacts.id}/crl/"
    revocations = "s3://${aws_s3_bucket.artifacts.id}/${var.revocations_s3_key}"
  }
}

output "crl_id" {
  description = "Terraform-managed CRL id (null unless crl_management_mode = \"awscc\")."
  value       = local.crl_owned_by_awscc ? awscc_rolesanywhere_crl.this[0].crl_id : null
}

output "crl_management_mode" {
  description = "Which actor owns the CRL object: awscc (declarative) or lambda (scheduled import)."
  value       = var.crl_management_mode
}

output "crl_issuer_function_name" {
  description = "CRL refresh Lambda (invoke manually with `aws lambda invoke --payload '{\"reason\":\"manual\"}'`)."
  value       = aws_lambda_function.crl_issuer.function_name
}

output "crl_issuer_role_arn" {
  description = "Role the ceremony stack's KMS key policy must allow to sign (its name is <name>-crl-issuer)."
  value       = aws_iam_role.crl_issuer.arn
}

output "crl_revoke_preconditions_met" {
  description = "False when CRL ownership is declarative but no PEM was supplied — workloads are rejected until a CRL exists."
  value       = !local.crl_owned_by_awscc || can(regex("-----BEGIN X509 CRL-----", local.crl_pem))
}

output "cloudhsm_backup_guard_policy_arn" {
  description = "Attach this policy to every principal that can manage CloudHSM (it denies backup deletion)."
  value       = aws_iam_policy.cloudhsm_backup_guard.arn
}

output "rolesanywhere_update_env" {
  description = "Values for the aws_signing_helper: no long-lived credentials, just the ARNs."
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
