# Turnkey: one command produces a working PKI.
#
#   terraform init && terraform apply
#
# With auto_bootstrap = true the apply does not return until the ceremony has
# SUCCEEDED (terraform_data.auto_bootstrap runs scripts/run_ceremony_and_wait.sh),
# so the trust anchor is ENABLED and a CRL is imported when apply finishes.
#
# Costs and caveats:
#   * an HSM runs for the duration (~$1.50/hr, typically 15-45 minutes);
#   * the machine running apply needs the AWS CLI with stepfunctions, ssm and
#     sts permissions — the waiter shells out to it;
#   * `terraform plan` shows the resource; the ceremony runs at apply time only;
#   * a failure fails the apply with the execution's cause, and the workflow's
#     cleanup still deletes the HSM and terminates the host.
#
# Unlike ../complete, this is not the fast path for CI: use it for a sandbox or
# a first bootstrap, not for a pipeline that only needs the infrastructure.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.67.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "pki" {
  source = "../../"

  name = "example-pki-auto"

  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"

  # The one difference from ../complete.
  auto_bootstrap                 = true
  auto_bootstrap_timeout_seconds = 3600

  workload_profiles = {
    batch = {
      description                = "Batch workers authenticating with X.509"
      managed_policy_arns        = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
      subject_condition_operator = "StringLike"
      allowed_subject_ou         = "platform"
      allowed_subject_cn         = "batch-*"
    }
  }

  tags = {
    Environment = "example"
    Owner       = "platform-security"
  }
}

output "trust_anchor_arn" {
  description = "ENABLED by the time this apply returns."
  value       = module.pki.trust_anchor_arn
}

output "profile_arns" {
  value = module.pki.profile_arns
}

output "workload_role_arns" {
  value = module.pki.workload_role_arns
}
