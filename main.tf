###############################################################################
# Composite module: the PKI engine plus the IAM Roles Anywhere consumer.
#
# Source this directory for the all-in-one stack (`examples/complete`), or source
# ./modules/hsm-ca and ./modules/roles-anywhere independently when the two halves
# should live in separate states (examples/standalone-hsm-ca shows the former).
###############################################################################

###############################################################################
# The composite stack passes the exact CRL issuer ARN to the CA key policy.
# Derive it deterministically instead of referencing the consumer module, which
# would create a cycle (the consumer takes the CA contract as an input).
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  crl_issuer_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.name}-crl-issuer"
  kms_signer_arns = var.allowed_kms_signer_role_arns != null ? var.allowed_kms_signer_role_arns : (
    var.enable_roles_anywhere ? [local.crl_issuer_role_arn] : []
  )
}

module "hsm_ca" {
  source = "./modules/hsm-ca"

  name                     = var.name
  permissions_boundary_arn = var.permissions_boundary_arn
  escrow_wait_minutes      = var.escrow_wait_minutes
  backup_retention_days    = var.backup_retention_days
  audit_log_retention_days = var.audit_log_retention_days
  vpc_id                   = var.vpc_id
  private_subnet_ids       = var.private_subnet_ids
  availability_zone        = var.availability_zone

  intermediate_key_spec         = var.intermediate_key_spec
  kms_deletion_window_in_days   = var.kms_deletion_window_in_days
  allowed_kms_signer_role_arns  = local.kms_signer_arns
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
  cloudhsm_cli_rpm_sha256        = var.cloudhsm_cli_rpm_sha256
  uv_version                     = var.uv_version
  uv_installer_sha256            = var.uv_installer_sha256
  commissioning_ca               = var.commissioning_ca
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

  ca_contract              = module.hsm_ca.ca_contract
  permissions_boundary_arn = var.permissions_boundary_arn
  workload_profiles        = var.workload_profiles

  revocations_s3_key = var.revocations_s3_key
  crl_validity_days  = var.crl_validity_days
  log_retention_days = var.log_retention_days
  tags               = var.tags
}

module "alb_mtls" {
  source = "./modules/alb-mtls"
  count  = var.enable_alb_mtls ? 1 : 0

  ca_contract              = module.hsm_ca.ca_contract
  permissions_boundary_arn = var.permissions_boundary_arn

  name                      = var.alb_mtls_name
  trust_store_name          = var.alb_trust_store_name
  revoked_serials_ssm_param = var.alb_revoked_serials_ssm_param
  revocations_s3_key        = var.revocations_s3_key
  crl_validity_days         = var.crl_validity_days
  log_retention_days        = var.log_retention_days
  tags                      = var.tags
}
