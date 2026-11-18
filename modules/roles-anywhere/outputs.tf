###############################################################################
# Outputs
###############################################################################

output "trust_anchor_arn" {
  description = "IAM Roles Anywhere trust anchor ARN. Created DISABLED; activated by the CAChainPublished event."
  value       = aws_rolesanywhere_trust_anchor.this.arn
}

output "trust_anchor_id" {
  description = "Trust anchor id (what the activation Lambda passes to UpdateTrustAnchor/EnableTrustAnchor)."
  value       = aws_rolesanywhere_trust_anchor.this.id
}

output "profile_arns" {
  description = "Map of workload key -> Roles Anywhere profile ARN."
  value       = { for key, profile in aws_rolesanywhere_profile.this : key => profile.arn }
}

output "workload_role_arns" {
  description = "Map of workload key -> IAM role ARN assumable through Roles Anywhere."
  value       = { for key, role in aws_iam_role.workload : key => role.arn }
}

output "rolesanywhere_update_env" {
  description = "Values for aws_signing_helper: no long-lived credentials, just the ARNs."
  value = {
    trust_anchor_arn = aws_rolesanywhere_trust_anchor.this.arn
    region           = var.ca_contract.region
    example_command = try(join(" ", [
      "aws_signing_helper credential-process",
      "--certificate /etc/pki/workload.pem",
      "--private-key /etc/pki/workload.key",
      "--trust-anchor-arn", aws_rolesanywhere_trust_anchor.this.arn,
      "--profile-arn", values(aws_rolesanywhere_profile.this)[0].arn,
      "--role-arn", values(aws_iam_role.workload)[0].arn,
    ]), null)
  }
}

output "crl_issuer_function_name" {
  description = "Activation + CRL refresh Lambda (invoke manually with `aws lambda invoke --payload '{\"reason\":\"manual\"}'`)."
  value       = aws_lambda_function.crl_issuer.function_name
}

output "crl_issuer_role_arn" {
  description = "Role that installs the chain and signs CRLs. The core key policy must list this exact ARN in allowed_kms_signer_role_arns."
  value       = aws_iam_role.crl_issuer.arn
}

output "activation_rule_name" {
  description = "EventBridge rule that fans CAChainPublished into this consumer."
  value       = aws_cloudwatch_event_rule.ca_chain_published.name
}

output "crl_refresh_rule_name" {
  description = "EventBridge rule for the routine CRL refresh."
  value       = aws_cloudwatch_event_rule.crl_refresh.name
}
