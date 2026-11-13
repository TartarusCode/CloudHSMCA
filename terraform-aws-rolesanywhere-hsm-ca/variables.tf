###############################################################################
# Inputs for terraform-aws-rolesanywhere-hsm-ca
#
# The module is two-phase by design (see README): while `ceremony_mode` is true
# it owns an HSM and an ephemeral signing host; while it is false it owns only
# the always-online pieces (KMS Intermediate CA, Roles Anywhere, CRL Lambda).
###############################################################################

variable "ceremony_mode" {
  description = <<-EOT
    Phase switch. true  = bootstrap / Root CA rotation: provisions the CloudHSM
    cluster + HSM, the ephemeral SSM ceremony host and the certificate
    parameters. false = steady state: destroys the HSM and ceremony host and
    provisions the Roles Anywhere trust anchor, profiles and workload roles.
    Deliberately has no default: choosing a phase must be explicit.
  EOT
  type        = bool
}

variable "name" {
  description = "Prefix for every resource, SSM path and IAM role name (lowercase, <=24 chars)."
  type        = string
  default     = "corp-pki"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name))
    error_message = "name must be 2-24 chars of lowercase letters, digits and hyphens."
  }
}

variable "vpc_id" {
  description = "VPC that already contains the private subnets used for the CloudHSM cluster and ceremony host."
  type        = string
}

variable "private_subnet_ids" {
  description = <<-EOT
    Private subnets (no NAT route required) for the CloudHSM cluster ENIs and
    the ceremony host. Subnet(s) must be in var.vpc_id. A single subnet gives a
    single-AZ cluster, which is all the ceremony needs: the encrypted cluster
    backup is retained after the HSM is deleted.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 1
    error_message = "At least one private subnet is required."
  }
}

variable "root_subject" {
  description = "Distinguished name of the offline Root CA (10-year, signed inside CloudHSM)."
  type = object({
    country             = optional(string, "US")
    state               = optional(string, "Washington")
    locality            = optional(string, "Seattle")
    organization        = optional(string, "Example Corp")
    organizational_unit = optional(string, "Platform Security")
    common_name         = optional(string, "Example Corp Root CA")
  })
  default = {}
}

variable "intermediate_subject" {
  description = "Distinguished name of the KMS-backed Intermediate CA (5-year, pathlen:0)."
  type = object({
    country             = optional(string, "US")
    state               = optional(string, "Washington")
    locality            = optional(string, "Seattle")
    organization        = optional(string, "Example Corp")
    organizational_unit = optional(string, "Platform Security")
    common_name         = optional(string, "Example Corp Issuing CA")
  })
  default = {}
}

variable "workload_profiles" {
  description = <<-EOT
    One Roles Anywhere profile + IAM role per workload class, keyed by a short
    stable name. The IAM trust policy is scoped to this module's trust anchor
    and, when set, to the x509 subject fields Roles Anywhere derives from the
    client certificate.

    allowed_subject_ou / allowed_subject_cn become conditions on
    aws:PrincipalTag/x509Subject/OU and aws:PrincipalTag/x509Subject/CN.
  EOT
  type = map(object({
    description                = optional(string, "Managed by terraform-aws-rolesanywhere-hsm-ca")
    session_duration_seconds   = optional(number, 3600)
    managed_policy_arns        = optional(list(string), [])
    session_policy_json        = optional(string) # Roles Anywhere session policy (JSON)
    accept_role_session_name   = optional(bool, true)
    subject_condition_operator = optional(string, "StringEquals")
    allowed_subject_ou         = optional(string)
    allowed_subject_cn         = optional(string)
    tags                       = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for p in values(var.workload_profiles) :
      p.session_duration_seconds >= 900 && p.session_duration_seconds <= 43200
    ])
    error_message = "session_duration_seconds must be between 900 and 43200 (STS limits)."
  }

  validation {
    condition = alltrue([
      for p in values(var.workload_profiles) :
      contains(["StringEquals", "StringLike"], p.subject_condition_operator)
    ])
    error_message = "subject_condition_operator must be StringEquals or StringLike."
  }
}

variable "intermediate_key_spec" {
  description = "KMS key spec for the Intermediate CA. P-384 is default; SHA-256 leaves are still issued by it."
  type        = string
  default     = "ECC_NIST_P384"

  validation {
    condition     = contains(["ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521"], var.intermediate_key_spec)
    error_message = "Only ECC_NIST_P256, ECC_NIST_P384 and ECC_NIST_P521 are FIPS 140-3 Level 3 SIGN_VERIFY specs in KMS."
  }
}

variable "root_key_curve" {
  description = "CloudHSM curve for the non-exportable Root CA key."
  type        = string
  default     = "secp384r1"

  validation {
    condition     = contains(["secp384r1", "secp521r1", "secp256r1"], var.root_key_curve)
    error_message = "root_key_curve must be secp384r1, secp521r1 or secp256r1."
  }
}

variable "root_ca_validity_days" {
  description = "Root CA lifetime. The key is offline, so 10 years is normal."
  type        = number
  default     = 3650
}

variable "intermediate_ca_validity_days" {
  description = "Intermediate CA lifetime. Keep it shorter than the Root CA."
  type        = number
  default     = 1825
}

variable "leaf_validity_days" {
  description = "Default lifetime of workload certificates issued with scripts/kms_ca_tool.py sign-leaf-csr."
  type        = number
  default     = 90
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the Lambda's 24h refresh cadence comfortably."
  type        = number
  default     = 7
}

variable "ceremony_instance_type" {
  description = "Instance type for the ephemeral ceremony host (Amazon Linux 2023, no public IP)."
  type        = string
  default     = "t3.small"
}

variable "artifact_bucket_name" {
  description = "Explicit S3 bucket name for certificates, CRLs and audit artifacts. Empty = generated unique name."
  type        = string
  default     = ""
}

variable "object_lock_mode" {
  description = "S3 Object Lock default retention mode. COMPLIANCE is recommended for certificate artifacts and cannot be shortened."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "S3 Object Lock default retention period in days."
  type        = number
  default     = 30
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period before the Intermediate CA key can be destroyed."
  type        = number
  default     = 30
}

variable "intermediate_signer_principal_arns" {
  description = "Extra IAM principals (e.g. your issuance pipeline role) allowed to GetPublicKey/Sign with the Intermediate CA key."
  type        = list(string)
  default     = []
}

variable "auto_bootstrap_crl" {
  description = <<-EOT
    Phase 2 only: invoke the CRL Lambda once during apply so a CRL exists
    before the first certificate is presented. Requires the AWS CLI on the
    machine running terraform apply, with rolesanywhere/lambda permissions.
  EOT
  type        = bool
  default     = true
}

variable "crl_bootstrap_generation" {
  description = "Bump to re-run the one-shot CRL bootstrap (e.g. after rotating the Intermediate CA)."
  type        = number
  default     = 1
}

variable "backup_guard_role_names" {
  description = "Additional IAM role NAMES that receive the deny-CloudHSM-backup-deletion policy (break-glass and automation roles)."
  type        = list(string)
  default     = []
}

variable "revocations_s3_key" {
  description = "S3 key (inside the artifact bucket) holding the revoked-serial JSON read by the CRL Lambda."
  type        = string
  default     = "revocations/revoked.json"
}

variable "log_retention_days" {
  description = "Retention for the CRL Lambda log group."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
