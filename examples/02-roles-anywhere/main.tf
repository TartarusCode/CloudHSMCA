# Step 2 of 2: the runtime — trust anchor, profiles, workload roles, CRL.
#
# Apply this only after the ceremony execution has reached SUCCEEDED: the chain
# is an input here, and a missing or incomplete chain fails at the trust
# anchor's precondition with the command that produces it. That is the whole
# point of the split — one apply, no phase flag, nothing deleted behind you.
#
#   terraform init
#   terraform apply -var intermediate_kms_key_arn=<from ../01-pki-ceremony>
#
# This example uses crl_management_mode = "lambda", so no CRL file has to exist
# at apply time: the scheduled Lambda owns the CRL object and the module invokes
# it once during the apply.

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
  source = "../../modules/roles-anywhere"

  # Must match the ceremony stack's name: the chain is read from /<name>/pki/*.pem.
  name = "example-pki"

  intermediate_kms_key_arn = var.intermediate_kms_key_arn

  crl_management_mode = "lambda"

  # The deny-list that protects the Root CA backup, applied to the role that
  # runs the ceremony (its name is deterministic).
  backup_guard_role_names = ["example-pki-ceremony-host"]

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
