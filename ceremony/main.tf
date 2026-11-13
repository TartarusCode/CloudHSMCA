###############################################################################
# ceremony/ — the Root CA ceremony as an imperative workflow (Shape B)
#
# Terraform owns the durable half: the CloudHSM cluster shell, the artifact
# bucket, the SSM hand-over parameters, IAM, and the state machine. Step
# Functions owns the ephemeral half exclusively — cloudhsmv2:CreateHsm,
# ec2:RunInstances, ssm:SendCommand, cloudhsmv2:DeleteHsm,
# ec2:TerminateInstances — so no HSM or ceremony host ever exists in Terraform
# state and nothing can drift.
#
# The runtime stack (terraform-aws-rolesanywhere-hsm-ca) consumes the chain this
# publishes, which is what makes it a single deterministic apply.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge(var.tags, {
    Module = "pki-ceremony"
    Tier   = "root-of-trust"
  })

  ssm_prefix              = "/${var.name}/pki"
  ssm_root_ca_pem         = "${local.ssm_prefix}/root_ca.pem"
  ssm_intermediate_ca_pem = "${local.ssm_prefix}/intermediate_ca.pem"
  ssm_ca_bundle_pem       = "${local.ssm_prefix}/ca_bundle.pem"
  ssm_ceremony_state      = "${local.ssm_prefix}/ceremony/state"
  ssm_hsm_admin_password  = "${local.ssm_prefix}/ceremony/hsm-admin-password"
  ssm_hsm_cu_password     = "${local.ssm_prefix}/ceremony/hsm-cu-password"

  pending = "PENDING-CEREMONY"

  # The bootstrap script is the runtime module's own ceremony script, rendered
  # here so both paths execute one implementation.
  bootstrap_config = {
    name                 = var.name
    region               = local.region
    cluster_id           = aws_cloudhsm_v2_cluster.this.cluster_id
    hsm_ip               = ""
    bucket               = aws_s3_bucket.artifacts.id
    kms_key_arn          = aws_kms_key.intermediate_ca.arn
    root_curve           = var.root_key_curve
    root_digest          = local.root_digest
    root_label           = local.hsm_root_key_label
    public_key_der       = "/opt/pki/root_ca_pub.der"
    root_validity_days   = var.root_ca_validity_days
    inter_validity_days  = var.intermediate_ca_validity_days
    ssm_root_ca_pem      = local.ssm_root_ca_pem
    ssm_intermediate_pem = local.ssm_intermediate_ca_pem
    ssm_ca_bundle_pem    = local.ssm_ca_bundle_pem
    ssm_ceremony_state   = local.ssm_ceremony_state
    ssm_admin_password   = local.ssm_hsm_admin_password
    ssm_cu_password      = local.ssm_hsm_cu_password
    s3_kms_ca_tool       = "scripts/kms_ca_tool.py"
    s3_root_ca_cnf       = "scripts/root_ca.cnf"
    s3_intermediate_cnf  = "scripts/intermediate_ca.cnf"
    cu_username          = var.hsm_crypto_user
    cloudhsm_cli_rpm     = var.cloudhsm_cli_rpm
  }

  rotate_config = {
    name                 = var.name
    region               = local.region
    cluster_id           = aws_cloudhsm_v2_cluster.this.cluster_id
    bucket               = aws_s3_bucket.artifacts.id
    kms_key_arn          = aws_kms_key.intermediate_ca.arn
    root_curve           = var.root_key_curve
    root_digest          = local.root_digest
    root_label           = local.hsm_root_key_label
    public_key_der       = "/opt/pki/root_ca_pub.der"
    inter_validity_days  = var.intermediate_ca_validity_days
    ssm_root_ca_pem      = local.ssm_root_ca_pem
    ssm_intermediate_pem = local.ssm_intermediate_ca_pem
    ssm_ca_bundle_pem    = local.ssm_ca_bundle_pem
    ssm_ceremony_state   = local.ssm_ceremony_state
    ssm_cu_password      = local.ssm_hsm_cu_password
    s3_kms_ca_tool       = "scripts/kms_ca_tool.py"
    s3_intermediate_cnf  = "scripts/intermediate_ca.cnf"
    cu_username          = var.hsm_crypto_user
    cloudhsm_cli_rpm     = var.cloudhsm_cli_rpm
  }

  root_digest = {
    secp256r1 = "sha256"
    secp384r1 = "sha384"
    secp521r1 = "sha512"
  }[var.root_key_curve]

  intermediate_digest = {
    ECC_NIST_P256 = "sha256"
    ECC_NIST_P384 = "sha384"
    ECC_NIST_P521 = "sha512"
  }[var.intermediate_key_spec]

  cnf_vars = {
    root_dn_section         = "root_dn"
    root_curve              = var.root_key_curve
    root_digest             = local.root_digest
    root_subject            = var.root_subject
    intermediate_dn_section = "intermediate_dn"
    intermediate_digest     = local.intermediate_digest
    intermediate_key_spec   = var.intermediate_key_spec
    intermediate_subject    = var.intermediate_subject
  }

  hsm_root_key_label = "root-ca-${var.name}"

  ca_signing_algorithm = {
    ECC_NIST_P256 = "ECDSA_SHA_256"
    ECC_NIST_P384 = "ECDSA_SHA_384"
    ECC_NIST_P521 = "ECDSA_SHA_512"
  }[var.intermediate_key_spec]

  # Both roles exist only in the account, not necessarily at key-creation time,
  # so the key policy names them by `aws:PrincipalArn` condition (see below).
  runtime_crl_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/${var.name}-crl-issuer"

  ca_key_principal_arns = compact(concat(
    [aws_iam_role.ceremony_host.arn, local.runtime_crl_role_arn],
    var.additional_signer_principal_arns,
  ))

  statemachine_definition = templatefile("${path.module}/statemachine.asl.json.tftpl", {
    name                       = var.name
    cluster_id                 = aws_cloudhsm_v2_cluster.this.cluster_id
    availability_zone          = var.availability_zone
    ami_id                     = data.aws_ami.al2023.id
    instance_type              = var.ceremony_instance_type
    subnet_id                  = var.private_subnet_ids[0]
    ceremony_security_group_id = aws_security_group.ceremony.id
    instance_profile_arn       = aws_iam_instance_profile.ceremony_host.arn
    bucket                     = aws_s3_bucket.artifacts.id
    bootstrap_key              = aws_s3_object.bootstrap_script[0].key
    rotate_key                 = aws_s3_object.rotate_script.key
  })
}

###############################################################################
# The durable cluster shell
#
# Created once and never deleted by the ceremony. It holds the backups that
# escrow the Root key, and its state is what the workflow branches on.
###############################################################################

resource "aws_cloudhsm_v2_cluster" "this" {
  hsm_type   = "hsm2m.medium"
  mode       = "FIPS"
  subnet_ids = var.private_subnet_ids
  tags       = merge(local.tags, { Name = "${var.name}-hsm-cluster" })
}

###############################################################################
# Ephemeral host prerequisites (network only — no instance is declared here)
###############################################################################

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "ceremony" {
  name_prefix = "${var.name}-ceremony-"
  description = "Egress-only security group for the ephemeral ceremony host"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-ceremony" })

  # No ingress: the workflow drives the host through SSM Session Manager only.

  egress {
    description = "AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "CloudHSM customer HSM ports, to the cluster security group only"
    from_port       = 2223
    to_port         = 2225
    protocol        = "tcp"
    security_groups = [aws_cloudhsm_v2_cluster.this.security_group_id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# Artifacts
###############################################################################

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix       = "${var.name}-ceremony-"
  bucket              = var.artifact_bucket_name != "" ? var.artifact_bucket_name : null
  force_destroy       = false
  object_lock_enabled = false
  tags                = local.tags
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The tooling and the two OpenSSL profiles, byte-identical to the runtime
# module's copies.
resource "aws_s3_object" "kms_ca_tool" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/kms_ca_tool.py"
  content                = file("${path.module}/scripts/kms_ca_tool.py")
  content_type           = "text/x-python"
  etag                   = filemd5("${path.module}/scripts/kms_ca_tool.py")
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "root_ca_cnf" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/root_ca.cnf"
  content                = templatefile("${path.module}/scripts/root_ca.cnf.tftpl", local.cnf_vars)
  content_type           = "text/plain"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "intermediate_ca_cnf" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/intermediate_ca.cnf"
  content                = templatefile("${path.module}/scripts/intermediate_ca.cnf.tftpl", local.cnf_vars)
  content_type           = "text/plain"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

# Bootstrap is the runtime module's own ceremony script; the entrypoint only
# downloads it and executes it, so the two paths cannot diverge.
resource "aws_s3_object" "bootstrap_script" {
  count = var.enable_bootstrap ? 1 : 0

  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/hsm_ceremony.sh"
  content                = templatefile("${path.module}/scripts/hsm_ceremony.sh.tftpl", { ceremony_config = jsonencode(local.bootstrap_config) })
  content_type           = "text/x-shellscript"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "rotate_script" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/rotate_intermediate.sh"
  content                = templatefile("${path.module}/scripts/rotate_intermediate.sh.tftpl", { rotate_config = jsonencode(local.rotate_config) })
  content_type           = "text/x-shellscript"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "bootstrap_entrypoint" {
  count = var.enable_bootstrap ? 1 : 0

  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/bootstrap.sh"
  content                = templatefile("${path.module}/scripts/bootstrap.sh.tftpl", { artifact_bucket = aws_s3_bucket.artifacts.id })
  content_type           = "text/x-shellscript"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

###############################################################################
# SSM hand-over parameters (the artifact the runtime stack consumes)
###############################################################################

resource "random_password" "hsm_admin" {
  count            = var.enable_bootstrap ? 1 : 0
  length           = 32
  special          = true
  override_special = "_-+=:."
}

resource "random_password" "hsm_cu" {
  length           = 32
  special          = true
  override_special = "_-+=:."
}

resource "aws_ssm_parameter" "hsm_admin_password" {
  count       = var.enable_bootstrap ? 1 : 0
  name        = local.ssm_hsm_admin_password
  description = "Bootstrap password of the unactivated CloudHSM admin user"
  type        = "SecureString"
  value       = random_password.hsm_admin[0].result
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "hsm_cu_password" {
  name        = local.ssm_hsm_cu_password
  description = "Password of the CloudHSM crypto user that owns the Root key"
  type        = "SecureString"
  value       = random_password.hsm_cu.result
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "root_ca_pem" {
  name        = local.ssm_root_ca_pem
  description = "Offline Root CA certificate (public key material only)"
  type        = "String"
  value       = local.pending
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "intermediate_ca_pem" {
  name        = local.ssm_intermediate_ca_pem
  description = "KMS Intermediate CA certificate"
  type        = "String"
  value       = local.pending
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ca_bundle_pem" {
  name        = local.ssm_ca_bundle_pem
  description = "CERTIFICATE_BUNDLE: Root CA followed by Intermediate CA"
  type        = "String"
  value       = local.pending
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ceremony_state" {
  name        = local.ssm_ceremony_state
  description = "Progress marker written by the ceremony host"
  type        = "String"
  value       = "NOT_STARTED"
  tags        = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

###############################################################################
# Ceremony host IAM — the role the workflow attaches to the instance it creates
###############################################################################

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ceremony_host" {
  name                 = "${var.name}-ceremony-host"
  description          = "Ephemeral host that runs the CloudHSM Root CA ceremony"
  assume_role_policy   = data.aws_iam_policy_document.ec2_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "ceremony_ssm_core" {
  role       = aws_iam_role.ceremony_host.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "ceremony_host" {
  statement {
    sid = "ReadCeremonyArtifacts"
    actions = [
      "s3:GetObject",
    ]
    resources = ["${aws_s3_bucket.artifacts.arn}/scripts/*"]
  }

  statement {
    sid       = "WriteCertificates"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/certs/*"]
  }

  statement {
    sid = "ReadCeremonyParameters"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = [
      for path in [
        local.ssm_root_ca_pem,
        local.ssm_intermediate_ca_pem,
        local.ssm_ca_bundle_pem,
        local.ssm_ceremony_state,
        local.ssm_hsm_admin_password,
        local.ssm_hsm_cu_password,
      ] : "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${path}"
    ]
  }

  statement {
    sid       = "WriteCeremonyState"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_prefix}/*"]
  }

  statement {
    sid       = "DecryptSecureParameters"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${local.region}.amazonaws.com"]
    }
  }

  # The key policy delegates to the account root under an aws:PrincipalArn
  # condition, so signing also needs this identity grant. Both are required:
  # the key policy cannot grant anything the identity policy does not allow
  # once the principal is the account rather than this role.
  #
  # Split in two: `kms:MessageType` and `kms:SigningAlgorithm` do not exist on a
  # GetPublicKey request, so one statement carrying them for both actions would
  # deny the read outright.
  statement {
    sid       = "SignIntermediateKey"
    actions   = ["kms:Sign"]
    resources = [aws_kms_key.intermediate_ca.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = [local.ca_signing_algorithm]
    }
  }

  statement {
    sid       = "ReadIntermediateKey"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = [aws_kms_key.intermediate_ca.arn]
  }

  statement {
    sid       = "DescribeHsmCluster"
    actions   = ["cloudhsm:DescribeClusters"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ceremony_host" {
  name   = "ceremony-host"
  role   = aws_iam_role.ceremony_host.id
  policy = data.aws_iam_policy_document.ceremony_host.json
}

resource "aws_iam_instance_profile" "ceremony_host" {
  name = "${var.name}-ceremony-host"
  role = aws_iam_role.ceremony_host.name
  tags = local.tags
}

###############################################################################
# Intermediate CA key (KMS asymmetric, never exportable)
#
# The ceremony stack creates it, so the "foundation" is one apply: the workflow
# needs GetPublicKey + Sign to build the Intermediate CSR, and the runtime
# module needs Sign for CRLs and leaf issuance. The policy matches both by
# `aws:PrincipalArn` under the account-root principal — the runtime module's
# <name>-crl-issuer may not exist yet, and KMS refuses (or rewrites) role
# principals it cannot resolve. Because that delegates to IAM, each signer also
# carries an identity-policy grant with the same digest-only conditions.
###############################################################################

data "aws_iam_policy_document" "intermediate_ca_key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # Signing is restricted to raw-digest requests with the single algorithm that
  # matches the key spec, so this key cannot be repurposed as a general signer.
  #
  # The principals are named by an `aws:PrincipalArn` condition rather than by
  # listing the role ARNs in `Principal`, for two reasons that both bite on the
  # first apply:
  #   * KMS resolves principals when the policy is written, so a role that does
  #     not exist yet (the runtime module's <name>-crl-issuer, which may be
  #     applied later) fails the apply with MalformedPolicyDocumentException.
  #   * KMS rewrites a role principal ARN to its principal ID (AROA…), so the
  #     stored policy stops matching the role ARN and every plan shows a diff.
  # With the account root as the principal and the role ARNs in a condition, the
  # policy is written unchanged and the role is matched when it is used.
  statement {
    sid       = "CaSignDigestOnly"
    actions   = ["kms:Sign"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.ca_key_principal_arns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = [local.ca_signing_algorithm]
    }
  }

  # Read/metadata actions are a separate statement on purpose: the condition
  # keys above do not exist on GetPublicKey, so folding them together would
  # deny every non-signing call.
  statement {
    sid       = "CaPublicKeyRead"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.ca_key_principal_arns
    }
  }
}

resource "aws_kms_key" "intermediate_ca" {
  description = "${var.name} IAM Roles Anywhere Intermediate CA (${var.intermediate_key_spec})"
  key_usage   = "SIGN_VERIFY"
  # `key_spec` exists in aws 5.x but is gone in 6.x; `customer_master_key_spec`
  # is accepted by both, which the declared range needs.
  customer_master_key_spec = var.intermediate_key_spec
  policy                   = data.aws_iam_policy_document.intermediate_ca_key.json
  deletion_window_in_days  = var.kms_deletion_window_in_days
  enable_key_rotation      = false # asymmetric KMS keys cannot be rotated
  multi_region             = false
  tags                     = local.tags
}

resource "aws_kms_alias" "intermediate_ca" {
  name          = "alias/${var.name}-intermediate-ca"
  target_key_id = aws_kms_key.intermediate_ca.key_id
}

###############################################################################
# Step Functions: role + log group + state machine
###############################################################################

resource "aws_cloudwatch_log_group" "ceremony" {
  name              = "/aws/states/${var.name}-ceremony"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.name}-ceremony-sfn"
  description        = "Drives the CloudHSM Root CA ceremony"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "sfn" {
  statement {
    sid = "HsmLifecycle"
    actions = [
      "cloudhsmv2:CreateHsm",
      "cloudhsmv2:DeleteHsm",
      "cloudhsmv2:DescribeClusters",
      "cloudhsmv2:DescribeBackups",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CeremonyHostLifecycle"
    actions = [
      "ec2:RunInstances",
      "ec2:TerminateInstances",
      "ec2:CreateTags",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PassCeremonyHostRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.ceremony_host.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  statement {
    sid = "DriveTheHost"
    actions = [
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
      "ssm:DescribeInstanceInformation",
      "ssm:ListCommandInvocations",
    ]
    resources = ["*"]
  }

  statement {
    sid = "Logs"
    actions = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "XRay"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "ceremony-sfn"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "ceremony" {
  name       = "${var.name}-ceremony"
  role_arn   = aws_iam_role.sfn.arn
  type       = "STANDARD"
  definition = local.statemachine_definition

  logging_configuration {
    level                  = "ALL"
    include_execution_data = true
    log_destination        = "${aws_cloudwatch_log_group.ceremony.arn}:*"
  }

  tracing_configuration {
    enabled = true
  }

  tags = local.tags
}
