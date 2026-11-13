terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 5.67.0 is the first release that can create hsm2m.medium clusters
      # (aws_cloudhsm_v2_cluster.mode = "FIPS"). Verified verifying against
      # 5.100.0 and 6.73.0 schemas: both expose mode/hsm2m.medium, and neither
      # has an aws_rolesanywhere_crl resource (see roles_anywhere.tf).
      version = ">= 5.67.0, < 7.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0" # source { content = ... } for the CRL Lambda
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}
