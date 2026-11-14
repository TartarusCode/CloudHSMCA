terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 5.67.0 is the first release that can create hsm2m.medium clusters
      # (aws_cloudhsm_v2_cluster.mode = "FIPS"). Verified against the 5.100.0 and
      # 6.73.0 schemas.
      version = ">= 5.67.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}
