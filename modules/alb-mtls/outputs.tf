###############################################################################
# Outputs
###############################################################################

output "trust_store_arn" {
  description = "ELBv2 trust store ARN. Point an HTTPS listener's mutual-TLS policy at it: aws_lb_listener.mutual_authentication { mode = \"verify\" trust_store_arn = ... }."
  value       = aws_lb_trust_store.this.arn
}

output "trust_store_name" {
  description = "Trust store name (max 32 chars)."
  value       = aws_lb_trust_store.this.name
}

output "bundle_s3_uri" {
  description = "Where the active CA bundle lives (the Lambda keeps it current)."
  value       = "s3://${var.ca_contract.artifacts_bucket}/${local.bundle_key}"
}

output "crl_s3_uri" {
  description = "Where the active PEM CRL lives."
  value       = "s3://${var.ca_contract.artifacts_bucket}/${local.crl_key}"
}

output "sync_function_name" {
  description = "Activation + CRL rotation Lambda (invoke manually with `aws lambda invoke --payload '{\"reason\":\"manual\"}'`)."
  value       = aws_lambda_function.sync.function_name
}

output "sync_role_arn" {
  description = "Role that signs CRLs. Its name keeps the <ca_name>- prefix the CA's key policy matches on."
  value       = aws_iam_role.sync.arn
}

output "activation_rule_name" {
  description = "EventBridge rule that fans CAChainPublished into this consumer."
  value       = aws_cloudwatch_event_rule.ca_chain_published.name
}

output "crl_refresh_rule_name" {
  description = "EventBridge rule for the routine CRL rotation."
  value       = aws_cloudwatch_event_rule.crl_refresh.name
}
