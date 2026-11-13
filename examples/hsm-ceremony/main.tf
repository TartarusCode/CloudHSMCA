# Phase 1: the Root CA ceremony.
#
# Creates the CloudHSM cluster + one HSM (~$1.50/hr while it exists) and the
# ephemeral Amazon Linux 2023 host that runs the ceremony. There is no inbound
# access to that host: reach it with SSM Session Manager.
#
#   terraform init && terraform apply
#   terraform output -raw ceremony_ssm_connect_command | bash
#
# Then switch to ../steady-state. The phase-2 apply is what terminates the HSM;
# CloudHSM keeps the encrypted cluster backup that holds the Root CA key.

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
  ceremony_mode = true

  # A private subnet with no NAT route is enough: the ceremony host talks to the
  # HSM over the cluster security group and to AWS APIs over the VPC endpoints
  # or a NAT gateway, whichever your VPC already has.
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]

  # Nothing Roles Anywhere-shaped exists until the ceremony has produced a chain.
  workload_profiles = {}

  tags = {
    Environment = "example"
    Owner       = "platform-security"
  }
}

output "ceremony_ssm_connect_command" {
  value = module.pki.ceremony_ssm_connect_command
}

output "cloudhsm_cluster_id" {
  value = module.pki.cloudhsm_cluster_id
}

output "certificate_parameters" {
  value = module.pki.certificate_parameters
}
