###############################################################################
# Inputs for the IAM Roles Anywhere consumer.
#
# It knows nothing about CloudHSM, the ceremony or S3 layout: everything comes
# from `ca_contract`, the output of modules/hsm-ca, and the chain arrives through
# the CAChainPublished event.
###############################################################################

variable "ca_contract" {
  description = "The ca_contract output of modules/hsm-ca: ARNs, SSM parameter names, artifact bucket, signing algorithm and event contract."
  type = object({
    name       = string
    region     = string
    account_id = string
    partition  = string

    cluster_id                 = string
    artifacts_bucket           = string
    artifacts_bucket_arn       = string
    intermediate_kms_key_arn   = string
    intermediate_kms_key_alias = string
    intermediate_key_spec      = string
    signing_algorithm          = string

    root_ca_ssm_param         = string
    intermediate_ca_ssm_param = string
    ca_bundle_ssm_param       = string
    ceremony_state_ssm_param  = string

    event_bus_name    = string
    event_source      = string
    event_detail_type = string

    state_machine_arn = string
    log_group_name    = string
  })

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:.+:key/.+$", var.ca_contract.intermediate_kms_key_arn))
    error_message = "ca_contract.intermediate_kms_key_arn must be a KMS key ARN."
  }

  validation {
    condition     = startswith(var.ca_contract.ca_bundle_ssm_param, "/")
    error_message = "ca_contract.ca_bundle_ssm_param must be an SSM parameter path starting with /."
  }
}

variable "workload_profiles" {
  description = <<-EOT
    One Roles Anywhere profile + IAM role per workload class, keyed by a short
    stable name. allowed_subject_ou / allowed_subject_cn become conditions on
    aws:PrincipalTag/x509Subject/OU and /CN.
  EOT
  type = map(object({
    description              = optional(string, "Managed by cloudhsmca")
    session_duration_seconds = optional(number, 3600)
    # IAM roles have a 3600 s floor; Roles Anywhere profiles accept 900 s.
    # Leave null to floor the role automatically, or set an explicit ceiling.
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
      p.role_max_session_duration == null ? true : (
        p.role_max_session_duration >= 3600 && p.role_max_session_duration <= 43200
      )
    ])
    error_message = "role_max_session_duration must be between 3600 and 43200 (IAM role limit)."
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
  description = "S3 key inside the CA artifact bucket holding the revoked-serial JSON the Lambda reads."
  type        = string
  default     = "revocations/revoked.json"
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the 24h refresh cadence."
  type        = number
  default     = 7
}

variable "crl_refresh_schedule" {
  description = "EventBridge schedule expression for the routine CRL refresh."
  type        = string
  default     = "rate(24 hours)"
}

variable "log_retention_days" {
  description = "Retention for the Lambda's log group."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource. `Module = \"cloudhsmca\"` is always added."
  type        = map(string)
  default     = {}
}
