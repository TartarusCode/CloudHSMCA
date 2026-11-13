# Phase 2: steady state.
#
# Destroys the HSM and the ceremony host (the CloudHSM backup survives), reads
# the certificate chain from SSM, and creates the Roles Anywhere trust anchor,
# one IAM role + profile per workload, and the CRL.
#
# This example uses crl_management_mode = "lambda", so no CRL file has to exist
# at apply time: the scheduled Lambda owns the CRL object and the module invokes
# it once during the apply.
#
#   terraform init && terraform apply

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.67.0, < 7.0.0"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = ">= 1.0.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

provider "awscc" {
  region = "us-east-1"
}

module "pki" {
  source = "../../terraform-aws-rolesanywhere-hsm-ca"

  name          = "example-pki"
  ceremony_mode = false

  # Only used by the phase-1 resources; kept so the same configuration can be
  # flipped back to true for a Root CA rotation.
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]

  crl_management_mode = "lambda"

  workload_profiles = {
    # A batch service: certificates must carry OU=platform and CN=batch-*, and
    # the resulting session may only read one bucket.
    batch = {
      description                = "Batch workers authenticating with X.509"
      session_duration_seconds   = 3600
      managed_policy_arns        = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
      subject_condition_operator = "StringLike"
      allowed_subject_ou         = "platform"
      allowed_subject_cn         = "batch-*"
      session_policy_json = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect   = "Allow"
          Action   = ["s3:GetObject"]
          Resource = "arn:aws:s3:::example-batch-input/*"
        }]
      })
    }

    # An observability agent: exact CN, no managed policies at all.
    agent = {
      description              = "Read-only metrics shipper"
      allowed_subject_ou       = "platform"
      allowed_subject_cn       = "metrics-agent"
      session_duration_seconds = 900
    }
  }

  tags = {
    Environment = "example"
    Owner       = "platform-security"
  }
}

output "trust_anchor_arn" {
  value = module.pki.trust_anchor_arn
}

output "profile_arns" {
  value = module.pki.profile_arns
}

output "workload_role_arns" {
  value = module.pki.workload_role_arns
}

output "rolesanywhere_update_env" {
  value = module.pki.rolesanywhere_update_env
}
