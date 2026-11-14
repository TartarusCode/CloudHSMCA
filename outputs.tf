###############################################################################
# Composite module outputs.
#
# Everything the PKI engine publishes, plus the Roles Anywhere consumer's ARNs
# when it is enabled.
###############################################################################

output "ca_contract" {
  description = "The workload-agnostic contract: key and bucket ARNs, SSM parameter names, signing algorithm, event bus/source/detail-type."
  value       = module.hsm_ca.ca_contract
}

output "intermediate_kms_key_arn" {
  description = "The KMS Intermediate CA key: signs workload certificates and CRLs, never exportable."
  value       = module.hsm_ca.ca_contract.intermediate_kms_key_arn
}

output "state_machine_arn" {
  description = "Run the ceremony with `aws stepfunctions start-execution`."
  value       = module.hsm_ca.state_machine_arn
}

output "start_bootstrap_command" {
  description = "Start a bootstrap ceremony (the cluster must be UNINITIALIZED). Prints the execution ARN."
  value       = module.hsm_ca.start_bootstrap_command
}

output "start_rotation_command" {
  description = "Start an intermediate rotation (needs a READY cluster backup). Prints the execution ARN."
  value       = module.hsm_ca.start_rotation_command
}

output "cloudhsm_cluster_id" {
  description = "Durable cluster shell. Its backups escrow the Root CA key."
  value       = module.hsm_ca.cloudhsm_cluster_id
}

output "certificate_parameters" {
  description = "SSM Parameter Store paths the ceremony publishes and biometric consumers read."
  value = {
    root_ca_pem         = module.hsm_ca.ca_contract.root_ca_ssm_param
    intermediate_ca_pem = module.hsm_ca.ca_contract.intermediate_ca_ssm_param
    ca_bundle_pem       = module.hsm_ca.ca_contract.ca_bundle_ssm_param
    ceremony_state      = module.hsm_ca.ca_contract.ceremony_state_ssm_param
  }
}

output "artifact_bucket" {
  description = "Bucket holding the tooling, issued certificates, CRLs and revocation input."
  value       = module.hsm_ca.ca_contract.artifacts_bucket
}

output "trust_anchor_arn" {
  description = "IAM Roles Anywhere trust anchor (null when enable_roles_anywhere = false). Created DISABLED; the ceremony's event activates it."
  value       = try(module.roles_anywhere[0].trust_anchor_arn, null)
}

output "trust_anchor_id" {
  description = "Trust anchor id (null when enable_roles_anywhere = false)."
  value       = try(module.roles_anywhere[0].trust_anchor_id, null)
}

output "profile_arns" {
  description = "Map of workload key -> Roles Anywhere profile ARN (empty when disabled)."
  value       = try(module.roles_anywhere[0].profile_arns, {})
}

output "workload_role_arns" {
  description = "Map of workload key -> IAM role ARN assumable through Roles Anywhere (empty when disabled)."
  value       = try(module.roles_anywhere[0].workload_role_arns, {})
}

output "rolesanywhere_update_env" {
  description = "Values for aws_signing_helper (null when disabled)."
  value       = try(module.roles_anywhere[0].rolesanywhere_update_env, null)
}

output "crl_issuer_function_name" {
  description = "Activation + CRL refresh Lambda (null when disabled)."
  value       = try(module.roles_anywhere[0].crl_issuer_function_name, null)
}

output "cloudhsm_backup_guard_policy_arn" {
  description = "Attach this policy to every principal that can manage CloudHSM (it denies backup deletion)."
  value       = module.hsm_ca.cloudhsm_backup_guard_policy_arn
}

output "alb_trust_store_arn" {
  description = "ELBv2 trust store ARN for aws_lb_listener.mutual_authentication (null when enable_alb_mtls = false)."
  value       = try(module.alb_mtls[0].trust_store_arn, null)
}

output "alb_trust_store_name" {
  description = "ELBv2 trust store name (null when disabled)."
  value       = try(module.alb_mtls[0].trust_store_name, null)
}

output "alb_sync_function_name" {
  description = "ALB trust-store activation + CRL rotation Lambda (null when disabled)."
  value       = try(module.alb_mtls[0].sync_function_name, null)
}
