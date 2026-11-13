terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 5.67.0 is the first release that can create hsm2m.medium clusters.
      version = ">= 5.67.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

###############################################################################
# The ceremony stack: durable cluster shell + Step Functions workflow.
#
# Inputs split into three groups: where it runs (network), what it signs with
# (the runtime module's KMS key), and where the artifact goes (SSM paths).
###############################################################################

variable "name" {
  description = "Prefix for every resource, SSM path and role name. Must match the runtime module's `name` so the SSM paths line up."
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

variable "intermediate_key_spec" {
  description = "Key spec of the Intermediate CA key, which this stack creates. Also drives the digest in the OpenSSL profiles."
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

variable "artifact_bucket_name" {
  description = "Explicit bucket name for ceremony artifacts. Empty = generated unique name."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Retention for the state machine's execution log."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
