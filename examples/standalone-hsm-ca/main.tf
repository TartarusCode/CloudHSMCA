# The PKI engine alone: no Roles Anywhere, no consumer of any kind.
#
#   terraform init && terraform apply       # ~45 s, no HSM created by apply
#   terraform output -raw start_bootstrap_command | bash
#   aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
#
# What you get afterwards: a Root CA whose key exists only in the CloudHSM
# backup, an Intermediate CA in KMS, and the chain in SSM Parameter Store. Use it
# for ALB / API Gateway mTLS, a VPN, internal TLS, or anything else that takes a
# PEM bundle — and subscribe to the CAChainPublished event instead of waiting for
# Terraform:
#
#   aws events put-rule --name my-mtls --event-pattern '{
#     "source": ["cloudhsmca.pki"],
#     "detail-type": ["CAChainPublished"],
#     "detail": {"ca_name": ["standalone-pki"]}}'
#
# The leaf issuance tool is in the module: scripts/kms_ca_tool.py sign-leaf-csr.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.67.0, < 7.0.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "hsm_ca" {
  source = "../../modules/hsm-ca"

  name = "standalone-pki"

  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"

  # Nothing consumes the chain inside Terraform: an ALB, an API Gateway or a VPN
  # picks it up from SSM (or from the event), which is why this module has no
  # consumer inputs at all.
  enable_bootstrap = true
  auto_bootstrap   = false

  tags = {
    Environment = "example"
    Owner       = "platform-security"
  }
}

output "ca_contract" {
  description = "Key/bucket ARNs, SSM parameter names, signing algorithm, event contract."
  value       = module.hsm_ca.ca_contract
}

output "start_bootstrap_command" {
  value = module.hsm_ca.start_bootstrap_command
}

output "cloudhsm_cluster_id" {
  value = module.hsm_ca.cloudhsm_cluster_id
}
