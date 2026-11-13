# One module, one apply.
#
#   terraform init && terraform apply        # ~45 s: everything, trust anchor DISABLED
#   terraform output -raw start_bootstrap_command | bash
#   aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
#
# The ceremony is what installs the real chain, enables the trust anchor and
# imports the first CRL, so workloads can authenticate as soon as it succeeds.
# For a single command that also waits for the ceremony, see ../auto-bootstrap.
#
# No HSM exists after apply: the workflow creates one, runs the ceremony, deletes
# it, and proves a READY backup escrows the Root key before it reports success.

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

  name = "example-pki"

  # A private subnet with no NAT route is enough: the ephemeral host talks to
  # the HSM over the cluster security group and to AWS APIs over whatever egress
  # the VPC already provides.
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"

  # false (the default) = apply does not wait for a ceremony. The operator runs
  # start_bootstrap_command, or flips this to true in ../auto-bootstrap.
  auto_bootstrap = false

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

output "start_bootstrap_command" {
  value = module.pki.start_bootstrap_command
}

output "trust_anchor_arn" {
  description = "Created DISABLED; the ceremony enables it."
  value       = module.pki.trust_anchor_arn
}

output "profile_arns" {
  value = module.pki.profile_arns
}

output "workload_role_arns" {
  value = module.pki.workload_role_arns
}

output "intermediate_kms_key_arn" {
  value = module.pki.intermediate_kms_key_arn
}

output "certificate_parameters" {
  value = module.pki.certificate_parameters
}

output "cloudhsm_cluster_id" {
  value = module.pki.cloudhsm_cluster_id
}
