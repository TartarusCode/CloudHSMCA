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

    An empty list is the safe default: only the ceremony host can sign. Pass the
    exact ARNs of designated signing services (for example the CRL issuer) to
    grant them access. Wildcards are rejected because a workload role that
    matches the pattern would otherwise enter the CA key's authorization
    boundary; the digest-only conditions cannot distinguish a CRL from a
    certificate signature.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.allowed_kms_signer_role_arns : !can(regex("[*?]", arn))])
    error_message = "allowed_kms_signer_role_arns must contain exact IAM role ARNs; wildcards would admit workload roles."
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
  description = "Instance type for the ephemeral ceremony host. Nano and micro sizes are rejected: the ceremony builds a venv, installs the CloudHSM CLI and runs OpenSSL, which those shapes cannot do reliably."
  type        = string
  default     = "t3.small"

  validation {
    condition     = !contains(["t2.nano", "t2.micro", "t3.nano", "t3.micro"], var.ceremony_instance_type)
    error_message = "ceremony_instance_type must be at least t3.small (t2.nano, t2.micro, t3.nano and t3.micro are rejected)."
  }
}

variable "hsm_crypto_user" {
  description = "CloudHSM crypto user that owns the Root key. It survives in the backup, so rotation re-uses it. CloudHSM allows only letters, digits and underscore."
  type        = string
  default     = "pki_cu"

  validation {
    condition     = can(regex("^[A-Za-z0-9_]{1,64}$", var.hsm_crypto_user))
    error_message = "hsm_crypto_user may contain only letters, digits and underscore: CloudHSM rejects any other character."
  }
}

variable "cloudhsm_cli_rpm" {
  description = "AWS CloudHSM Client SDK 5 CLI package for Amazon Linux 2023."
  type        = string
  default     = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"
}

variable "cloudhsm_cli_rpm_sha256" {
  description = "SHA-256 of the CloudHSM CLI RPM. Required: the ceremony verifies the download before installing a package that can reach the root key."
  type        = string
  default     = ""
}

variable "uv_version" {
  description = "Exact uv release the ceremony installs."
  type        = string
  default     = "0.5.11"
}

variable "uv_installer_sha256" {
  description = "Optional SHA-256 of the uv install script. Strongly recommended; without it the installer is pinned only by uv_version."
  type        = string
  default     = ""
}

###############################################################################
# Cluster commissioning
###############################################################################

variable "commissioning_ca" {
  description = <<-EOT
    The separate, approved CA that claims a NEW CloudHSM cluster. Terraform
    creates clusters UNINITIALIZED; the ceremony must sign the cluster CSR and
    call InitializeCluster before it can activate the cluster. The private key
    never enters Terraform state: supply either an SSM SecureString parameter
    name holding it, or a pre-signed cluster certificate (fully offline mode).
    The certificate is public and is installed as the client's trust anchor.
  EOT
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

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary ARN attached to every role this module creates. Null leaves roles unbounded."
  type        = string
  default     = null

  validation {
    condition     = var.permissions_boundary_arn == null || can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:policy/.+$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be an IAM policy ARN."
  }
}

variable "escrow_wait_minutes" {
  description = "Minutes the workflow waits for the deletion-triggered escrow backup to reach READY. DeleteHsm triggers the backup; it is polled every 60 seconds, so this is also the maximum number of polls."
  type        = number
  default     = 60

  validation {
    condition     = var.escrow_wait_minutes >= 1 && var.escrow_wait_minutes <= 1440
    error_message = "escrow_wait_minutes must be between 1 and 1440 (24 hours)."
  }
}

variable "backup_retention_days" {
  description = "Days CloudHSM keeps cluster backups. The escrow backup holds the only copy of the Root key after the ephemeral HSM is deleted."
  type        = number
  default     = 90

  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 379
    error_message = "backup_retention_days must be between 7 and 379."
  }
}

variable "audit_log_retention_days" {
  description = "Retention for the CloudHSM audit log group /aws/cloudhsm/<cluster-id>."
  type        = number
  default     = 90

  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545,
    731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.audit_log_retention_days)
    error_message = "audit_log_retention_days must be a retention value CloudWatch Logs accepts."
  }
}
