###############################################################################
# Composite module: the PKI engine plus the IAM Roles Anywhere consumer.
#
# Source this directory for the all-in-one stack (`examples/complete`), or source
# ./modules/hsm-ca and ./modules/roles-anywhere independently when the two halves
# should live in separate states (examples/standalone-hsm-ca shows the former).
###############################################################################

module "hsm_ca" {
  source = "./modules/hsm-ca"

  name               = var.name
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  availability_zone  = var.availability_zone

  intermediate_key_spec         = var.intermediate_key_spec
  kms_deletion_window_in_days   = var.kms_deletion_window_in_days
  allowed_kms_signer_role_arns  = var.allowed_kms_signer_role_arns
  root_key_curve                = var.root_key_curve
  root_ca_validity_days         = var.root_ca_validity_days
  intermediate_ca_validity_days = var.intermediate_ca_validity_days
  root_subject                  = var.root_subject
  intermediate_subject          = var.intermediate_subject

  enable_bootstrap               = var.enable_bootstrap
  auto_bootstrap                 = var.auto_bootstrap
  auto_bootstrap_timeout_seconds = var.auto_bootstrap_timeout_seconds
  ceremony_instance_type         = var.ceremony_instance_type
  hsm_crypto_user                = var.hsm_crypto_user
  cloudhsm_cli_rpm               = var.cloudhsm_cli_rpm
  event_bus_name                 = var.event_bus_name

  artifact_bucket_name = var.artifact_bucket_name
  object_lock_mode     = var.object_lock_mode
  object_lock_days     = var.object_lock_days
  log_retention_days   = var.log_retention_days
  tags                 = var.tags
}

module "roles_anywhere" {
  source = "./modules/roles-anywhere"
  count  = var.enable_roles_anywhere ? 1 : 0

  ca_contract       = module.hsm_ca.ca_contract
  workload_profiles = var.workload_profiles

  revocations_s3_key = var.revocations_s3_key
  crl_validity_days  = var.crl_validity_days
  log_retention_days = var.log_retention_days
  tags               = var.tags
}
