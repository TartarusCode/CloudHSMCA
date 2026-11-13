# Step 1 of 2: the foundation + the ceremony state machine.
#
# Creates the durable cluster shell, the artifact bucket, the Intermediate CA
# key, the SSM hand-over parameters, IAM, and the Step Functions workflow. No
# HSM exists after apply: the workflow creates one, runs the ceremony, deletes
# it, and proves a READY backup exists.
#
#   terraform init && terraform apply
#   terraform output -raw start_bootstrap_command | bash
#   aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
#
# Then examples/02-roles-anywhere, which consumes the chain this publishes.

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
  }
}

provider "aws" {
  region = "us-east-1"
}

module "ceremony" {
  source = "../../modules/pki-ceremony"

  name = "example-pki"

  # A private subnet with no NAT route is enough: the ephemeral host talks to
  # the HSM over the cluster security group and to AWS APIs over whatever egress
  # the VPC already provides.
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"

  # The workflow branches on the cluster state; this only controls whether the
  # bootstrap entrypoint and admin password are published.
  enable_bootstrap = true

  tags = {
    Environment = "example"
    Owner       = "platform-security"
  }
}

output "start_bootstrap_command" {
  value = module.ceremony.start_bootstrap_command
}

output "intermediate_kms_key_arn" {
  description = "Pass this to examples/02-roles-anywhere as intermediate_kms_key_arn."
  value       = module.ceremony.intermediate_kms_key_arn
}

output "ceremony_host_role_name" {
  description = "The ceremony host role's name (already granted signing on the key)."
  value       = "example-pki-ceremony-host"
}

output "certificate_parameters" {
  value = module.ceremony.certificate_parameters
}

output "cloudhsm_cluster_id" {
  value = module.ceremony.cloudhsm_cluster_id
}
