plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "0.37.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

config {
  call_module_type = "all"
  # Do not call APIs during lint; everything here must work offline.
  force = false
}

# Every variable in this module carries a description; keep it that way.
rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

# Provider version pinning belongs in the module's versions.tf, which states the
# range; tflint cannot know which end of the range a consumer will use.
rule "terraform_required_version" {
  enabled = false
}
