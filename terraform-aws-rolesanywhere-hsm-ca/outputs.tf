###############################################################################
# Outputs
###############################################################################

output "ceremony_ssm_connect_command" {
  description = "SSM Session Manager command for the ephemeral ceremony host (empty in steady state)."
  value = var.ceremony_mode ? join(" ", [
    "aws ssm start-session --target",
    aws_instance.ceremony[0].id,
    "--region",
    local.region,
  ]) : "ceremony_mode is false — set ceremony_mode = true to re-run the Root CA ceremony"
}

output "ceremony_instance_id" {
  description = "Instance id of the ceremony host (null in steady state)."
  value       = var.ceremony_mode ? aws_instance.ceremony[0].id : null
}

output "cloudhsm_cluster_id" {
  description = "CloudHSM cluster id. The cluster (and its retained encrypted backup) outlives the HSM."
  value       = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "cloudhsm_cluster_state" {
  description = "CloudHSM cluster state at apply time."
  value       = aws_cloudhsm_v2_cluster.this.cluster_state
}

output "hsm_instance_id" {
  description = "Ceremony HSM id (null in steady state; the encrypted backup is what remains)."
  value       = var.ceremony_mode ? aws_cloudhsm_v2_hsm.ceremony[0].hsm_id : null
}

output "intermediate_kms_key_arn" {
  description = "KMS asymmetric key that signs workload certificates and CRLs."
  value       = aws_kms_key.intermediate_ca.arn
}

output "intermediate_kms_key_alias" {
  description = "Alias of the Intermediate CA key."
  value       = aws_kms_alias.intermediate_ca.name
}

output "certificate_parameters" {
  description = "SSM parameters holding the certificate chain (written by the ceremony host)."
  value = {
    root_ca_pem         = local.ssm_root_ca_pem
    intermediate_ca_pem = local.ssm_intermediate_ca_pem
    ca_bundle_pem       = local.ssm_ca_bundle_pem
    ceremony_state      = local.ssm_ceremony_state
  }
}

output "artifact_bucket" {
  description = "S3 bucket holding certificates, CSRs, CRLs and revocation input."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_prefixes" {
  description = "Where the ceremony, the Lambda and operators read and write artifacts."
  value = {
    certs       = "s3://${aws_s3_bucket.artifacts.id}/certs/"
    crl         = "s3://${aws_s3_bucket.artifacts.id}/crl/"
    revocations = "s3://${aws_s3_bucket.artifacts.id}/${var.revocations_s3_key}"
  }
}

output "trust_anchor_arn" {
  description = "IAM Roles Anywhere trust anchor ARN (null in ceremony mode)."
  value       = local.phase2 ? aws_rolesanywhere_trust_anchor.this[0].arn : null
}

output "profile_arns" {
  description = "Map of workload key -> Roles Anywhere profile ARN."
  value       = { for key, profile in aws_rolesanywhere_profile.this : key => profile.arn }
}

output "workload_role_arns" {
  description = "Map of workload key -> IAM role ARN assumable through Roles Anywhere."
  value       = { for key, role in aws_iam_role.workload : key => role.arn }
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

output "crl_revoke_preconditions_met" {
  description = "False when CRL ownership is declarative but no PEM was supplied — workloads are rejected until a CRL exists."
  value       = !local.crl_owned_by_awscc || can(regex("-----BEGIN X509 CRL-----", local.crl_pem))
}

output "cloudhsm_backup_guard_policy_arn" {
  description = "Attach this policy to every principal that can manage CloudHSM (it denies backup deletion)."
  value       = aws_iam_policy.cloudhsm_backup_guard.arn
}

output "rolesanywhere_update_env" {
  description = "Values for the aws_signing_helper: no long-lived credentials, just the endpoint and profile ARN."
  value = {
    trust_anchor_arn = local.phase2 ? aws_rolesanywhere_trust_anchor.this[0].arn : null
    region           = local.region
    example_command = try(join(" ", [
      "aws_signing_helper credential-process",
      "--certificate /etc/pki/workload.pem",
      "--private-key /etc/pki/workload.key",
      "--trust-anchor-arn", aws_rolesanywhere_trust_anchor.this[0].arn,
      "--profile-arn", values(aws_rolesanywhere_profile.this)[0].arn,
      "--role-arn", values(aws_iam_role.workload)[0].arn,
    ]), null)
  }
}
