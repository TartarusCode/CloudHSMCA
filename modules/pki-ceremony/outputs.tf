output "state_machine_arn" {
  description = "Run the ceremony with `aws stepfunctions start-execution`."
  value       = aws_sfn_state_machine.ceremony.arn
}

output "start_bootstrap_command" {
  description = "Start a bootstrap ceremony (cluster must be UNINITIALIZED)."
  value = join(" ", [
    "aws stepfunctions start-execution",
    "--state-machine-arn", aws_sfn_state_machine.ceremony.arn,
    "--name", "bootstrap-$(date -u +%Y%m%dT%H%M%SZ)",
    "--input", jsonencode({ mode = "BOOTSTRAP" }),
  ])
}

output "start_rotation_command" {
  description = "Start an Intermediate CA rotation (needs a READY cluster backup)."
  value = join(" ", [
    "aws stepfunctions start-execution",
    "--state-machine-arn", aws_sfn_state_machine.ceremony.arn,
    "--name", "rotate-$(date -u +%Y%m%dT%H%M%SZ)",
    "--input", jsonencode({ mode = "ROTATE_INTERMEDIATE" }),
  ])
}

output "intermediate_kms_key_arn" {
  description = "The Intermediate CA key this stack created. Pass it to the runtime module as `intermediate_kms_key_arn`."
  value       = aws_kms_key.intermediate_ca.arn
}

output "intermediate_kms_key_alias" {
  description = "Alias of the Intermediate CA key."
  value       = aws_kms_alias.intermediate_ca.name
}

output "ceremony_host_role_arn" {
  description = "Role that runs the ceremony. Give it to the runtime module's `backup_guard_role_names` (its name is <name>-ceremony-host) so the backup deny covers it."
  value       = aws_iam_role.ceremony_host.arn
}

output "cloudhsm_cluster_id" {
  description = "Durable cluster shell. Its backups escrow the Root CA key."
  value       = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "artifact_bucket" {
  description = "Bucket holding the ceremony tooling, profiles and published certificates."
  value       = aws_s3_bucket.artifacts.id
}

output "certificate_parameters" {
  description = "The artifact the runtime stack consumes, and the one it writes nothing to."
  value = {
    root_ca_pem         = local.ssm_root_ca_pem
    intermediate_ca_pem = local.ssm_intermediate_ca_pem
    ca_bundle_pem       = local.ssm_ca_bundle_pem
    ceremony_state      = local.ssm_ceremony_state
  }
}

output "execution_history_log_group" {
  description = "Every ceremony execution is logged here, with full execution data."
  value       = aws_cloudwatch_log_group.ceremony.name
}
