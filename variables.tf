###############################################################################
# Composite module inputs.
#
# The PKI-engine inputs are passed straight through to modules/hsm-ca; the
# consumer inputs go to modules/roles-anywhere, which can be switched off.
###############################################################################

variable "name" {
  description = "Prefix for every resource, SSM path and IAM role name. Consumers match the CAChainPublished event on this value."
  type        = string
  default     = "corp-pki"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name))
    error_message = "name must be 2-24 chars of lowercase letters, digits and hyphens."
  }
}

variable "vpc_id" {
  description = "VPC containing the private subnets for the CloudHSM cluster and the ceremony host."
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

variable "intermediate_key_spec" {
  description = "Key spec of the KMS Intermediate CA key."
  type        = string
  default     = "ECC_NIST_P384"
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period before the Intermediate CA key can be destroyed."
  type        = number
  default     = 30
}

variable "allowed_kms_signer_role_arns" {
  description = "Exact IAM role ARNs besides the ceremony host allowed to sign with the Intermediate key. null = the composite stack's designated CRL issuer role only; workload roles are never implied by a pattern."
  type        = list(string)
  default     = null
}

variable "root_key_curve" {
  description = "CloudHSM curve for the non-exportable Root CA key."
  type        = string
  default     = "secp384r1"
}

variable "root_ca_validity_days" {
  description = "Root CA lifetime (bootstrap only)."
  type        = number
  default     = 3650
}

variable "intermediate_ca_validity_days" {
  description = "Intermediate CA lifetime (bootstrap and rotation)."
  type        = number
  default     = 1825
}

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

variable "enable_bootstrap" {
  description = "true for a first-time cluster (publishes the bootstrap entrypoint and admin password); false for rotation-only."
  type        = bool
  default     = true
}

variable "auto_bootstrap" {
  description = "true runs the ceremony inside terraform apply and waits for it; false (default) leaves it to the operator."
  type        = bool
  default     = false
}

variable "auto_bootstrap_timeout_seconds" {
  description = "How long the auto_bootstrap waiter polls before failing the apply."
  type        = number
  default     = 3600
}

variable "ceremony_instance_type" {
  description = "Instance type for the ephemeral ceremony host."
  type        = string
  default     = "t3.small"
}

variable "hsm_crypto_user" {
  description = "CloudHSM crypto user that owns the Root key."
  type        = string
  default     = "pki-cu"
}

variable "cloudhsm_cli_rpm" {
  description = "AWS CloudHSM Client SDK 5 CLI package for Amazon Linux 2023."
  type        = string
  default     = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"
}

variable "cloudhsm_cli_rpm_sha256" {
  description = "SHA-256 of the CloudHSM CLI RPM, verified before the ceremony installs it. Required for a bootstrap."
  type        = string
  default     = ""
}

variable "uv_version" {
  description = "Exact uv release the ceremony installs."
  type        = string
  default     = "0.5.11"
}

variable "uv_installer_sha256" {
  description = "Optional SHA-256 of the uv install script."
  type        = string
  default     = ""
}

variable "commissioning_ca" {
  description = "The approved CA that claims a new CloudHSM cluster (public certificate plus an SSM SecureString parameter holding the key, or a pre-signed cluster certificate). Required for the first bootstrap of an UNINITIALIZED cluster."
  type = object({
    certificate                = string
    key_ssm_param              = optional(string, "")
    signed_cluster_certificate = optional(string, "")
  })
  default = {
    certificate                = ""
    key_ssm_param              = ""
    signed_cluster_certificate = ""
  }
}

variable "event_bus_name" {
  description = "EventBridge bus for CAChainPublished. Consumers must subscribe to the same bus."
  type        = string
  default     = "default"
}

variable "artifact_bucket_name" {
  description = "Explicit artifact bucket name. Empty = generated unique name."
  type        = string
  default     = ""
}

variable "object_lock_mode" {
  description = "S3 Object Lock default retention mode."
  type        = string
  default     = "GOVERNANCE"
}

variable "object_lock_days" {
  description = "S3 Object Lock default retention period in days."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "Retention for every log group this stack creates."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource. Module = \"cloudhsmca\" is always added."
  type        = map(string)
  default     = {}
}

###############################################################################
# Roles Anywhere consumer
###############################################################################

variable "enable_roles_anywhere" {
  description = "Create the IAM Roles Anywhere consumer (trust anchor, profiles, workload roles, CRL Lambda). false = PKI engine only."
  type        = bool
  default     = true
}

variable "workload_profiles" {
  description = "One Roles Anywhere profile + IAM role per workload class, keyed by a short stable name."
  type = map(object({
    description              = optional(string, "Managed by cloudhsmca")
    session_duration_seconds = optional(number, 3600)
    # IAM role ceiling: leave null to floor at 3600 automatically.
    role_max_session_duration  = optional(number)
    managed_policy_arns        = optional(list(string), [])
    session_policy_json        = optional(string)
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
      p.role_max_session_duration == null || (p.role_max_session_duration >= 3600 && p.role_max_session_duration <= 43200)
    ])
    error_message = "role_max_session_duration must be between 3600 and 43200 (IAM role limit)."
  }
}

variable "revocations_s3_key" {
  description = "S3 key inside the CA artifact bucket holding the revoked-serial JSON read by the CRL Lambda."
  type        = string
  default     = "revocations/revoked.json"
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the 24h refresh cadence."
  type        = number
  default     = 7
}

variable "enable_alb_mtls" {
  description = "Create the ALB mutual-TLS consumer (ELBv2 trust store + activation/CRL Lambda). false = no trust store."
  type        = bool
  default     = false
}

variable "alb_mtls_name" {
  description = "S3 prefix name for the ALB trust store artifacts (alb-mtls/<name>/). Empty = the CA's name."
  type        = string
  default     = ""
}

variable "alb_trust_store_name" {
  description = "Explicit ELBv2 trust store name (max 32 chars). Empty = <ca_name>-alb-mtls."
  type        = string
  default     = ""
}

variable "alb_revoked_serials_ssm_param" {
  description = "SSM parameter holding revoked serials as JSON for the ALB CRL. Empty = do not rotate the CRL; set to a parameter containing {\"revoked\": []} to explicitly clear serials. A configured but missing or invalid parameter fails closed."
  type        = string
  default     = ""
}
