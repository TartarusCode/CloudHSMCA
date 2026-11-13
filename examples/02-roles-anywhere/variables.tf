variable "intermediate_kms_key_arn" {
  description = "Intermediate CA key created by ../01-pki-ceremony: `terraform -chdir=../01-pki-ceremony output -raw intermediate_kms_key_arn`."
  type        = string
  # Placeholder so `terraform validate` works without the other stack applied.
  default = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", var.intermediate_kms_key_arn))
    error_message = "intermediate_kms_key_arn must be a KMS key ARN."
  }
}
