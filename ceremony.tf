###############################################################################
# ceremony.tf — the Root CA ceremony as an imperative workflow
#
# Terraform owns the durable half: the CloudHSM cluster shell, the artifact
# bucket, the SSM hand-over parameters, IAM, and the state machine. Step
# Functions owns the ephemeral half exclusively — cloudhsmv2:CreateHsm,
# ec2:RunInstances, ssm:SendCommand, cloudhsmv2:DeleteHsm,
# ec2:TerminateInstances — so no HSM or ceremony host ever exists in Terraform
# state and nothing can drift.
#
# The workflow also activates the runtime this module creates: UpdateTrustAnchor
# installs the real chain, EnableTrustAnchor flips the placeholder anchor on, and
# ImportOrUpdateCrl gives it a CRL — see the tail of statemachine.asl.json.tftpl.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  # One identity for every resource this module creates, so Cost Explorer and
  # Resource Groups do not have to know about the repository layout.
  module_tag = "cloudhsmca"

  tags = merge(var.tags, {
    Module = local.module_tag
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

  # The bootstrap script is the ceremony script itself, rendered
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

  # The key policy names the signers by `aws:PrincipalArn` under the account-root
  # principal, so KMS never has to resolve (or rewrite) a role principal — see
  # data.aws_iam_policy_document.intermediate_ca_key.
  ca_key_principal_arns = compact(concat(
    [aws_iam_role.ceremony_host.arn, aws_iam_role.crl_issuer.arn],
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

    # The activation tail: the workflow installs the chain it just built and
    # flips the placeholder trust anchor on.
    trust_anchor_id   = aws_rolesanywhere_trust_anchor.this.id
    trust_anchor_arn  = aws_rolesanywhere_trust_anchor.this.arn
    ssm_ca_bundle_pem = local.ssm_ca_bundle_pem
    crl_function_name = aws_lambda_function.crl_issuer.function_name
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
# The ceremony host's artifacts (the bucket itself is in main.tf)
###############################################################################

# The tooling and the two OpenSSL profiles.
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

# Bootstrap is the ceremony script itself; the entrypoint only
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
# SSM hand-over parameters (the chain the trust anchor and the Lambda read)
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
# The ceremony needs GetPublicKey + Sign to build the Intermediate CSR, and the
# CRL Lambda needs Sign for CRLs and leaf issuance. Both are matched by
# `aws:PrincipalArn` under the account-root principal: KMS resolves principals
# when the policy is written, and it rewrites a role principal to its AROA id, so
# naming the roles directly is fragile in an apply that creates them alongside the
# key. Because a root principal delegates the decision to IAM, each signer also
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
  #   * KMS resolves principals when the policy is written, so a role created in
  #     the same apply fails the key with MalformedPolicyDocumentException unless
  #     Terraform happens to order it first.
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

  # The activation tail of the workflow: install the chain it just published,
  # turn the placeholder trust anchor on, then have the CRL importer sign and
  # import the first CRL.
  statement {
    sid = "ActivateTrustAnchor"
    actions = [
      "rolesanywhere:UpdateTrustAnchor",
      "rolesanywhere:EnableTrustAnchor",
    ]
    resources = [aws_rolesanywhere_trust_anchor.this.arn]
  }

  statement {
    sid       = "ReadCaBundle"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_ca_bundle_pem}"]
  }

  statement {
    sid       = "InvokeCrlIssuer"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.crl_issuer.arn]
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

###############################################################################
# auto_bootstrap — one command, one apply
#
# With var.auto_bootstrap = false (the default) this does nothing: apply lands in
# under a minute with the trust anchor DISABLED and the operator starts the
# ceremony out of band. With true, a local-exec starts the bootstrap execution
# and polls it, so a failure fails the apply with the execution's cause instead
# of leaving a half-configured PKI behind.
#
# terraform_data rather than a data source: the side effect must run at apply,
# not during plan, and must re-run only when the state machine or name changes.
###############################################################################

resource "terraform_data" "auto_bootstrap" {
  count = var.auto_bootstrap ? 1 : 0

  triggers_replace = [
    aws_sfn_state_machine.ceremony.arn,
    var.name,
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      STATE_MACHINE_ARN = aws_sfn_state_machine.ceremony.arn
      SSM_CA_BUNDLE     = local.ssm_ca_bundle_pem
      PKI_NAME          = var.name
      AWS_REGION        = local.region
      WAIT_TIMEOUT      = tostring(var.auto_bootstrap_timeout_seconds)
    }
    command = "${path.module}/scripts/run_ceremony_and_wait.sh"
  }

  depends_on = [
    aws_sfn_state_machine.ceremony,
    aws_cloudhsm_v2_cluster.this,
    aws_kms_key.intermediate_ca,
    aws_rolesanywhere_trust_anchor.this,
    aws_iam_role_policy.sfn,
    aws_lambda_function.crl_issuer,
    aws_ssm_parameter.ca_bundle_pem,
  ]
}
