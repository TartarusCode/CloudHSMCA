terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 5.67.0 is the first release that can create hsm2m.medium clusters
      # (aws_cloudhsm_v2_cluster.mode = "FIPS"). Verified against the 5.100.0 and
      # 6.73.0 schemas: both expose mode/hsm2m.medium, and neither has an
      # aws_rolesanywhere_crl resource — the CRL is imported by the Lambda.
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
    tls = {
      source = "hashicorp/tls"
      # Only for the disabled placeholder trust anchor, so that the first apply
      # does not have to wait for a ceremony. See roles_anywhere.tf.
      version = ">= 4.0.0"
    }
  }
}
