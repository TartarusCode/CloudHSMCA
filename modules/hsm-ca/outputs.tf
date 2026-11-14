###############################################################################
# Outputs — the workload-agnostic contract
#
# `ca_contract` is the only thing a consumer module needs: ARNs, SSM parameter
# names, the artifact bucket and the EventBridge contract. It deliberately
# contains no Roles Anywhere, ALB, VPN or TLS concepts.
###############################################################################

output "ca_contract" {
  description = "Everything downstream consumers need: key and bucket ARNs, SSM parameter names, signing algorithm, and the CAChainPublished event contract."
  value = {
    name       = var.name
    region     = local.region
    account_id = local.account_id
    partition  = local.partition

    cluster_id                 = aws_cloudhsm_v2_cluster.this.cluster_id
    artifacts_bucket           = aws_s3_bucket.artifacts.id
    artifacts_bucket_arn       = aws_s3_bucket.artifacts.arn
    intermediate_kms_key_arn   = aws_kms_key.intermediate_ca.arn
    intermediate_kms_key_alias = aws_kms_alias.intermediate_ca.name
    intermediate_key_spec      = var.intermediate_key_spec
    signing_algorithm          = local.ca_signing_algorithm

    # Where the chain is published. A consumer reads these, never guesses them.
    root_ca_ssm_param         = local.ssm_root_ca_pem
    intermediate_ca_ssm_param = local.ssm_intermediate_ca_pem
    ca_bundle_ssm_param       = local.ssm_ca_bundle_pem
    ceremony_state_ssm_param  = local.ssm_ceremony_state

    # The fan-out contract: consumers subscribe to this source/detail-type and
    # match detail.ca_name == name.
    event_bus_name    = var.event_bus_name
    event_source      = "cloudhsmca.pki"
    event_detail_type = "CAChainPublished"

    state_machine_arn = aws_sfn_state_machine.ceremony.arn
    log_group_name    = aws_cloudwatch_log_group.ceremony.name
  }
}

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
    "--input", "'${jsonencode({ mode = "BOOTSTRAP" })}'",
    "--query", "executionArn", "--output", "text",
  ])
}

output "start_rotation_command" {
  description = "Start an Intermediate CA rotation (needs a READY cluster backup)."
  value = join(" ", [
    "aws stepfunctions start-execution",
    "--state-machine-arn", aws_sfn_state_machine.ceremony.arn,
    "--name", "rotate-$(date -u +%Y%m%dT%H%M%SZ)",
    "--input", "'${jsonencode({ mode = "ROTATE_INTERMEDIATE" })}'",
    "--query", "executionArn", "--output", "text",
  ])
}

output "cloudhsm_cluster_id" {
  description = "Durable cluster shell. Its backups escrow the Root CA key."
  value       = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "cloudhsm_backup_guard_policy_arn" {
  description = "Attach this policy to every principal, beyond the two here, that can manage CloudHSM (it denies backup deletion)."
  value       = aws_iam_policy.cloudhsm_backup_guard.arn
}

output "execution_history_log_group" {
  description = "Every ceremony execution is logged here, with full execution data."
  value       = aws_cloudwatch_log_group.ceremony.name
}
