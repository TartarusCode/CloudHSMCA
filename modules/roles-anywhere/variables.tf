###############################################################################
# Inputs for modules/roles-anywhere
#
# A CA consumer: it takes the chain published by modules/pki-ceremony and the KMS
# Intermediate key created there, and builds the Roles Anywhere runtime in one
# apply. No VPC, no HSM, no phase flag.
###############################################################################

variable "name" {
  description = "Prefix for every resource, SSM path and IAM role name. Must match the ceremony stack's `name`, which publishes /<name>/pki/*.pem."
  type        = string
  default     = "corp-pki"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name))
    error_message = "name must be 2-24 chars of lowercase letters, digits and hyphens."
  }
}

variable "intermediate_kms_key_arn" {
  description = <<-EOT
    The asymmetric SIGN_VERIFY key that signs workload certificates and CRLs.
    modules/pki-ceremony creates it, and its key policy allows this module's CRL role
    (`<name>-crl-issuer`) to sign with it, so pass
    `terraform output -raw intermediate_kms_key_arn` from that stack.
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", var.intermediate_kms_key_arn))
    error_message = "intermediate_kms_key_arn must be a KMS key ARN."
  }
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
    description                = optional(string, "Managed by roles-anywhere")
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

variable "crl_management_mode" {
  description = <<-EOT
    Who owns the CRL object. Exactly one actor may own it: an enabled CRL that
    stops being refreshed (nextUpdate in the past) is worse than no CRL at all.

    "awscc"  — awscc_rolesanywhere_crl manages it declaratively from
               var.crl_pem_path; refresh by re-applying (see README).
    "lambda" — the scheduled Lambda imports a new CRL every 24 hours through
               rolesanywhere:ImportCrl; Terraform does not track CRL objects.
  EOT
  type        = string
  default     = "awscc"

  validation {
    condition     = contains(["awscc", "lambda"], var.crl_management_mode)
    error_message = "crl_management_mode must be awscc or lambda."
  }
}

variable "crl_pem_path" {
  description = <<-EOT
    Path to the PEM CRL used when crl_management_mode = "awscc". Roles Anywhere
    ImportCrl takes PEM, and Terraform cannot sign, so the CRL is produced
    before apply, from the repository root:

      python3 modules/pki-ceremony/scripts/kms_ca_tool.py generate-crl --signer kms \
        --kms-key-id <intermediate_kms_key_arn> \
        --issuer-cert intermediate_ca.pem \
        --revoked-file revoked.json --out crl.pem
  EOT
  type        = string
  default     = ""
}

variable "revocations_s3_key" {
  description = "S3 key (inside the artifact bucket) holding the revoked-serial JSON read by the CRL Lambda."
  type        = string
  default     = "revocations/revoked.json"
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the Lambda's 24h refresh cadence comfortably."
  type        = number
  default     = 7
}

variable "artifact_bucket_name" {
  description = "Explicit S3 bucket name for CRLs, revocation input and audit copies. Empty = generated unique name."
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

variable "auto_bootstrap_crl" {
  description = <<-EOT
    With crl_management_mode = "lambda": invoke the CRL Lambda once during apply
    so a CRL exists before the first certificate is presented. Requires the AWS
    CLI on the machine running terraform apply, with rolesanywhere and lambda
    permissions.
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
  description = "IAM role NAMES that receive the deny-CloudHSM-backup-deletion policy (break-glass, automation, and the ceremony stack's ceremony host role)."
  type        = list(string)
  default     = []
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
