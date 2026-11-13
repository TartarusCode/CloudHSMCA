###############################################################################
# Inputs for the whole PKI, in one module and one apply.
#
# Reads top to bottom as: what it is called (name), where it runs (network),
# what it signs with (key material), what the certificates say (subjects), and
# how the workloads authenticate (workload_profiles).
###############################################################################

variable "name" {
  description = "Prefix for every resource, SSM path and IAM role name."
  type        = string
  default     = "corp-pki"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name))
    error_message = "name must be 2-24 chars of lowercase letters, digits and hyphens."
  }
}

variable "vpc_id" {
  description = "VPC containing the private subnets for the cluster ENIs and the ephemeral ceremony host."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the CloudHSM cluster. The ceremony host is launched in the first one."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 1
    error_message = "At least one private subnet is required."
  }
}

variable "availability_zone" {
  description = "AZ for the ceremony HSM. Must be an AZ of one of var.private_subnet_ids."
  type        = string
}

###############################################################################
# Key material
###############################################################################

variable "intermediate_key_spec" {
  description = "Key spec of the Intermediate CA key, which this module creates. Also drives the digest in the OpenSSL profiles."
  type        = string
  default     = "ECC_NIST_P384"

  validation {
    condition     = contains(["ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521"], var.intermediate_key_spec)
    error_message = "Only ECC_NIST_P256, ECC_NIST_P384 and ECC_NIST_P521 are supported."
  }
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period before the Intermediate CA key can be destroyed."
  type        = number
  default     = 30
}

variable "additional_signer_principal_arns" {
  description = "Extra IAM principals (e.g. your issuance pipeline role) matched by `aws:PrincipalArn` in the Intermediate CA key policy for digest-only kms:Sign. Each still needs its own identity-policy grant."
  type        = list(string)
  default     = []
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
  description = "Root CA lifetime. Only used by the bootstrap ceremony."
  type        = number
  default     = 3650
}

variable "intermediate_ca_validity_days" {
  description = "Intermediate CA lifetime. Used by both bootstrap and rotation."
  type        = number
  default     = 1825
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the Lambda's 24h refresh cadence comfortably."
  type        = number
  default     = 7
}

###############################################################################
# Certificate subjects
###############################################################################

variable "root_subject" {
  description = "Distinguished name of the offline Root CA."
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
  description = "Distinguished name of the KMS-backed Intermediate CA."
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

###############################################################################
# The ceremony
###############################################################################

variable "enable_bootstrap" {
  description = <<-EOT
    true  — this cluster has never been initialized, so publish the bootstrap
            entrypoint, the admin password and the Root CA inputs.
    false — rotation only: the Root key is restored from the cluster backup, and
            the admin password is not needed.
    Both entrypoints are always safe to publish; this flag only hides the ones a
    rotation must never use.
  EOT
  type        = bool
  default     = true
}

variable "auto_bootstrap" {
  description = <<-EOT
    false (default) — `terraform apply` lands in under a minute with the trust
      anchor DISABLED, and the operator starts the ceremony out of band:
      `terraform output -raw start_bootstrap_command | bash`.

    true — apply runs the ceremony itself (a terraform_data local-exec that
      starts the execution and polls until SUCCEEDED), so one command produces a
      working PKI. The ceremony takes ~15-45 minutes and needs the AWS CLI on the
      machine running apply.
  EOT
  type        = bool
  default     = false
}

variable "auto_bootstrap_timeout_seconds" {
  description = "How long the auto_bootstrap waiter polls the execution before failing the apply."
  type        = number
  default     = 3600
}

variable "ceremony_instance_type" {
  description = "Instance type for the ephemeral ceremony host."
  type        = string
  default     = "t3.small"
}

variable "hsm_crypto_user" {
  description = "CloudHSM crypto user that owns the Root key. It survives in the backup, so rotation re-uses it."
  type        = string
  default     = "pki-cu"
}

variable "cloudhsm_cli_rpm" {
  description = "AWS CloudHSM Client SDK 5 CLI package for Amazon Linux 2023."
  type        = string
  default     = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"
}

###############################################################################
# Workloads
###############################################################################

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
    description                = optional(string, "Managed by cloudhsmca")
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

variable "revocations_s3_key" {
  description = "S3 key (inside the artifact bucket) holding the revoked-serial JSON read by the CRL Lambda."
  type        = string
  default     = "revocations/revoked.json"
}

###############################################################################
# Artifacts and tags
###############################################################################

variable "artifact_bucket_name" {
  description = "Explicit bucket name for the ceremony tooling, CRLs and audit copies. Empty = generated unique name."
  type        = string
  default     = ""
}

variable "object_lock_mode" {
  description = "S3 Object Lock default retention mode. COMPLIANCE is recommended for CRL artifacts and cannot be shortened."
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

variable "log_retention_days" {
  description = "Retention for the state machine, ceremony host and CRL Lambda log groups."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource. `Module = \"cloudhsmca\"` is always added."
  type        = map(string)
  default     = {}
}
