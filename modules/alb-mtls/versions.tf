terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # aws_lb_trust_store and aws_lb_trust_store_revocation both exist in 5.x;
      # the module follows the CA module's range so the composite never has to
      # resolve two different provider majors.
      version = ">= 5.67.0, < 7.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}
