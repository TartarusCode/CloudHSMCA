###############################################################################
# Inputs for the ALB mutual-TLS consumer.
#
# Like the Roles Anywhere consumer, it knows nothing about CloudHSM or the
# ceremony: everything comes from `ca_contract`, and the chain arrives through
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
}

variable "name" {
  description = "Short name for this trust store's S3 prefix (alb-mtls/<name>/). Empty = the CA's name."
  type        = string
  default     = ""

  validation {
    condition     = var.name == "" || can(regex("^[a-z][a-z0-9-]{1,23}$", var.name))
    error_message = "name must be empty or 2-24 chars of lowercase letters, digits and hyphens."
  }
}

variable "trust_store_name" {
  description = "Explicit ELBv2 trust store name (max 32 chars, alphanumeric and hyphens). Empty = <ca_name>-alb-mtls."
  type        = string
  default     = ""
}

variable "revoked_serials_ssm_param" {
  description = "SSM parameter holding the revoked serials as JSON ({\"revoked\":[{\"serial\":\"0x0a1b\",\"revoked_at\":...,\"reason\":...}]}). Empty = issue an empty CRL."
  type        = string
  default     = ""
}

variable "crl_validity_days" {
  description = "thisUpdate -> nextUpdate window of every generated CRL. Must exceed the refresh cadence comfortably."
  type        = number
  default     = 7
}

variable "sync_schedule" {
  description = "EventBridge schedule expression for the routine CRL rotation."
  type        = string
  default     = "rate(24 hours)"
}

variable "log_retention_days" {
  description = "Retention for the sync Lambda's log group."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource. `Module = \"cloudhsmca\"` is always added."
  type        = map(string)
  default     = {}
}
