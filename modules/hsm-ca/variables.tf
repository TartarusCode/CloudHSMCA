###############################################################################
# Inputs for the workload-agnostic PKI engine.
#
# Nothing here mentions IAM Roles Anywhere, ALB, VPN or TLS: the module produces
# a Root CA (offline, in a CloudHSM that exists only during a ceremony), an
# Intermediate CA (KMS, always online) and publishes the chain to SSM. Consumers
# subscribe to the CAChainPublished event.
###############################################################################

variable "name" {
  description = "Prefix for every resource, SSM path and IAM role name. Consumers match the event on this value."
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

variable "allowed_kms_signer_role_arns" {
  description = <<-EOT
    IAM role ARNs, besides the ceremony host, allowed to use the Intermediate CA
    key for signing: kms:Sign under the digest-only conditions, plus
    GetPublicKey/DescribeKey. This is how a consumer module signs CRLs or leaf
    certificates without the core module having to know it exists — no circular
    key policy, no cross-stack resource reference.

    Defaults to every role whose name starts with "<name>-", which covers the
    conventional consumer role names in this repository. Narrow it, or pass
    explicit ARNs, if your naming differs.
  EOT
  type        = list(string)
  default     = null
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
    false (default) — `terraform apply` lands in under a minute and the operator
      starts the ceremony out of band:
      `terraform output -raw start_bootstrap_command | bash`.

    true — apply runs the ceremony itself (a terraform_data local-exec that
      starts the execution and polls until SUCCEEDED). The ceremony takes ~15-45
      minutes and needs the AWS CLI on the machine running apply.
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

variable "event_bus_name" {
  description = "EventBridge bus the CAChainPublished event is emitted on. Consumers must subscribe to the same bus."
  type        = string
  default     = "default"
}

###############################################################################
# Artifacts and tags
###############################################################################

variable "artifact_bucket_name" {
  description = "Explicit bucket name for the ceremony tooling, issued certificates, CRLs and audit copies. Empty = generated unique name."
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
  description = "Retention for the state machine, ceremony host and consumer log groups."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource. `Module = \"cloudhsmca\"` is always added."
  type        = map(string)
  default     = {}
}
