###############################################################################
# ceremony.tf — the Root CA ceremony as an imperative workflow
#
# Terraform owns the durable half: the CloudHSM cluster shell, the artifact
# bucket, the SSM hand-over parameters, IAM, and the state machine. Step
# Functions owns the ephemeral half exclusively — cloudhsm:CreateHsm,
# ec2:RunInstances, ssm:SendCommand, cloudhsm:DeleteHsm,
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
  ssm_verified_backup     = "${local.ssm_prefix}/ceremony/verified_backup_id"
  # HSM user passwords live in Secrets Manager, not SSM: the host gets a
  # scoped GetSecretValue instead of read access to a SecureString parameter.
  secret_hsm_admin_name = "${var.name}-ceremony-hsm-admin"
  secret_hsm_cu_name    = "${var.name}-ceremony-hsm-cu"

  pending = "PENDING-CEREMONY"

  # The bootstrap script is the ceremony script itself, rendered
  # here so both paths execute one implementation.
  bootstrap_config = {
    name                        = var.name
    region                      = local.region
    cluster_id                  = aws_cloudhsm_v2_cluster.this.cluster_id
    hsm_ip                      = ""
    bucket                      = aws_s3_bucket.artifacts.id
    kms_key_arn                 = aws_kms_key.intermediate_ca.arn
    root_curve                  = var.root_key_curve
    root_digest                 = local.root_digest
    root_label                  = local.hsm_root_key_label
    public_key_der              = "/opt/pki/root_ca_pub.der"
    root_validity_days          = var.root_ca_validity_days
    inter_validity_days         = var.intermediate_ca_validity_days
    ssm_root_ca_pem             = local.ssm_root_ca_pem
    ssm_intermediate_pem        = local.ssm_intermediate_ca_pem
    ssm_ca_bundle_pem           = local.ssm_ca_bundle_pem
    ssm_ceremony_state          = local.ssm_ceremony_state
    secret_admin_password       = aws_secretsmanager_secret.hsm_admin[0].arn
    secret_cu_password          = aws_secretsmanager_secret.hsm_cu.arn
    s3_kms_ca_tool              = "scripts/kms_ca_tool.py"
    s3_root_ca_cnf              = "scripts/root_ca.cnf"
    s3_intermediate_cnf         = "scripts/intermediate_ca.cnf"
    cu_username                 = var.hsm_crypto_user
    cloudhsm_cli_rpm            = var.cloudhsm_cli_rpm
    commissioning_ca_cert       = var.commissioning_ca.certificate
    commissioning_key_ssm_param = var.commissioning_ca.key_ssm_param
    commissioning_signed_cert   = var.commissioning_ca.signed_cluster_certificate
    s3_tool_version             = aws_s3_object.kms_ca_tool.version_id
    s3_root_cnf_version         = aws_s3_object.root_ca_cnf.version_id
    s3_inter_cnf_version        = aws_s3_object.intermediate_ca_cnf.version_id
    cloudhsm_cli_rpm_sha256     = var.cloudhsm_cli_rpm_sha256
    uv_version                  = var.uv_version
    uv_installer_sha256         = var.uv_installer_sha256
  }

  rotate_config = {
    name                    = var.name
    region                  = local.region
    cluster_id              = aws_cloudhsm_v2_cluster.this.cluster_id
    bucket                  = aws_s3_bucket.artifacts.id
    kms_key_arn             = aws_kms_key.intermediate_ca.arn
    root_curve              = var.root_key_curve
    root_digest             = local.root_digest
    root_label              = local.hsm_root_key_label
    public_key_der          = "/opt/pki/root_ca_pub.der"
    inter_validity_days     = var.intermediate_ca_validity_days
    ssm_root_ca_pem         = local.ssm_root_ca_pem
    ssm_intermediate_pem    = local.ssm_intermediate_ca_pem
    ssm_ca_bundle_pem       = local.ssm_ca_bundle_pem
    ssm_ceremony_state      = local.ssm_ceremony_state
    secret_cu_password      = aws_secretsmanager_secret.hsm_cu.arn
    s3_kms_ca_tool          = "scripts/kms_ca_tool.py"
    s3_intermediate_cnf     = "scripts/intermediate_ca.cnf"
    cu_username             = var.hsm_crypto_user
    cloudhsm_cli_rpm        = var.cloudhsm_cli_rpm
    commissioning_ca_cert   = var.commissioning_ca.certificate
    s3_tool_version         = aws_s3_object.kms_ca_tool.version_id
    s3_inter_cnf_version    = aws_s3_object.intermediate_ca_cnf.version_id
    cloudhsm_cli_rpm_sha256 = var.cloudhsm_cli_rpm_sha256
    uv_version              = var.uv_version
    uv_installer_sha256     = var.uv_installer_sha256
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

  # Exact ARNs only. The default empty list keeps workload roles out of the CA
  # key's authorization boundary.
  consumer_signer_arns = var.allowed_kms_signer_role_arns

  ca_key_principal_arns = compact(concat(
    [aws_iam_role.ceremony_host.arn],
    local.consumer_signer_arns,
  ))

  cluster_arn         = "arn:${local.partition}:cloudhsm:${local.region}:${local.account_id}:cluster/${aws_cloudhsm_v2_cluster.this.cluster_id}"
  ceremony_sg_arn     = "arn:${local.partition}:ec2:${local.region}:${local.account_id}:security-group/${aws_security_group.ceremony.id}"
  ceremony_ami_arn    = "arn:${local.partition}:ec2:${local.region}::image/${data.aws_ami.al2023.id}"
  ceremony_subnet_arn = "arn:${local.partition}:ec2:${local.region}:${local.account_id}:subnet/${var.private_subnet_ids[0]}"
  run_shell_doc_arn   = "arn:${local.partition}:ssm:${local.region}::document/AWS-RunShellScript"

  statemachine_definition = templatefile("${path.module}/statemachine.asl.json.tftpl", {
    name                       = var.name
    escrow_polls               = ceil(var.escrow_wait_minutes)
    cluster_id                 = aws_cloudhsm_v2_cluster.this.cluster_id
    availability_zone          = var.availability_zone
    ami_id                     = data.aws_ami.al2023.id
    instance_type              = var.ceremony_instance_type
    subnet_id                  = var.private_subnet_ids[0]
    ceremony_security_group_id = aws_security_group.ceremony.id
    instance_profile_arn       = aws_iam_instance_profile.ceremony_host.arn
    bucket                     = aws_s3_bucket.artifacts.id
    bootstrap_key              = try(aws_s3_object.bootstrap_script[0].key, "")
    rotate_key                 = aws_s3_object.rotate_script.key
    bootstrap_enabled          = var.enable_bootstrap
    verified_backup_param      = local.ssm_verified_backup
    lease_table                = aws_dynamodb_table.ceremony_lease.name

    # The fan-out: the workflow announces the chain on EventBridge and knows
    # nothing about who consumes it.
    event_bus_name       = var.event_bus_name
    ca_name              = var.name
    ca_bundle_ssm_pem    = local.ssm_ca_bundle_pem
    root_ca_ssm_pem      = local.ssm_root_ca_pem
    intermediate_ssm_pem = local.ssm_intermediate_ca_pem
    cluster_id_out       = aws_cloudhsm_v2_cluster.this.cluster_id
    kms_key_arn_out      = aws_kms_key.intermediate_ca.arn
    bucket_out           = aws_s3_bucket.artifacts.id
  })
}

###############################################################################
# One conditional lease per cluster
#
# A bootstrap and a rotation must never allocate two HSMs or write the same CA
# artifacts at once. The lease is owned by an execution; a lease whose owner is
# no longer running is reclaimed by the next run, so a timed-out or aborted
# execution cannot block the cluster indefinitely.
###############################################################################

resource "aws_dynamodb_table" "ceremony_lease" {
  name         = "${var.name}-ceremony-lease"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "lease_id"
  tags         = local.tags

  attribute {
    name = "lease_id"
    type = "S"
  }
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

# The provider's aws_cloudhsm_v2_cluster has no backup_retention_policy, but the
# API does and it needs no HSM, so the cluster-level window is applied here
# instead of silently keeping the 90-day service default. The escrow backup is
# the only copy of the Root key once the ephemeral HSM is deleted.
resource "terraform_data" "backup_retention" {
  triggers_replace = [
    aws_cloudhsm_v2_cluster.this.cluster_id,
    var.backup_retention_days,
  ]

  provisioner "local-exec" {
    command = "aws cloudhsmv2 modify-cluster --region ${local.region} --cluster-id ${aws_cloudhsm_v2_cluster.this.cluster_id} --backup-retention-policy Type=DAYS,Value=${var.backup_retention_days}"
  }
}

# CloudHSM writes its audit log to this exact group name. Managing it here makes
# the retention policy explicit and reviewable; a group that already exists (an
# older cluster) must be imported rather than recreated.
resource "aws_cloudwatch_log_group" "cluster_audit" {
  name              = "/aws/cloudhsm/${aws_cloudhsm_v2_cluster.this.cluster_id}"
  retention_in_days = var.audit_log_retention_days
  tags              = local.tags
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

# The cluster security group is created by CloudHSM with a self-referencing
# ingress rule only. The ephemeral host is a different group, so without this
# rule the cloudhsm-cli TLS connection to ports 2223-2225 is refused.
resource "aws_security_group_rule" "cluster_from_ceremony" {
  type                     = "ingress"
  description              = "CloudHSM customer HSM ports from the ceremony host"
  security_group_id        = aws_cloudhsm_v2_cluster.this.security_group_id
  source_security_group_id = aws_security_group.ceremony.id
  from_port                = 2223
  to_port                  = 2225
  protocol                 = "tcp"
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

# The alphabet excludes ':' (the HSM rejects it) and '$', '\', '`', quotes and
# spaces (shell and CLI argument expansion). The ceremony passes every password
# as --password=<value>, so a leading '-' cannot be parsed as a flag either.
resource "random_password" "hsm_admin" {
  count            = var.enable_bootstrap ? 1 : 0
  length           = 32
  special          = true
  override_special = "_-+=."
}

resource "random_password" "hsm_cu" {
  length           = 32
  special          = true
  override_special = "_-+=."
}

resource "aws_secretsmanager_secret" "hsm_admin" {
  count                   = var.enable_bootstrap ? 1 : 0
  name                    = local.secret_hsm_admin_name
  description             = "Bootstrap password of the unactivated CloudHSM admin user"
  recovery_window_in_days = 0 # bootstrap-only credential: delete with the stack
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "hsm_admin" {
  count         = var.enable_bootstrap ? 1 : 0
  secret_id     = aws_secretsmanager_secret.hsm_admin[0].id
  secret_string = random_password.hsm_admin[0].result
}

resource "aws_secretsmanager_secret" "hsm_cu" {
  name                    = local.secret_hsm_cu_name
  description             = "Password of the CloudHSM crypto user that owns the Root key"
  recovery_window_in_days = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "hsm_cu" {
  secret_id     = aws_secretsmanager_secret.hsm_cu.id
  secret_string = random_password.hsm_cu.result
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

# The workflow writes this only after it has observed a NEW, READY escrow
# backup. Consumers must not read a chain whose root has not been escrowed.
resource "aws_ssm_parameter" "verified_backup" {
  name        = local.ssm_verified_backup
  description = "Backup id verified as escrow for the latest CA ceremony"
  type        = "String"
  value       = local.pending
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
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "ceremony_ssm_core" {
  role       = aws_iam_role.ceremony_host.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_kms_alias" "ssm" {
  name = "alias/aws/ssm"
}


data "aws_iam_policy_document" "ceremony_host" {
  statement {
    sid = "ReadCeremonyArtifacts"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
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
      for path in concat([
        local.ssm_root_ca_pem,
        local.ssm_intermediate_ca_pem,
        local.ssm_ca_bundle_pem,
        local.ssm_ceremony_state,
      ], var.commissioning_ca.key_ssm_param != "" ? [var.commissioning_ca.key_ssm_param] : []) : "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${path}"
    ]
  }

  statement {
    sid       = "WriteCeremonyState"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_prefix}/*"]
  }

  # HSM user passwords come from Secrets Manager; the host may read exactly
  # these two secrets and nothing else. They use the service-managed key, which
  # Secrets Manager decrypts on the caller's behalf, so no kms:Decrypt is
  # needed here (and none is granted).
  statement {
    sid     = "ReadHsmSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = concat(
      [aws_secretsmanager_secret.hsm_cu.arn],
      var.enable_bootstrap ? [aws_secretsmanager_secret.hsm_admin[0].arn] : [],
    )
  }

  statement {
    sid       = "DecryptSecureParameters"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_alias.ssm.target_key_arn]

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

  # Claiming a newly created cluster is part of the bootstrap: sign its CSR and
  # call InitializeCluster before the CLI can activate it.
  statement {
    sid       = "InitializeHsmCluster"
    actions   = ["cloudhsm:InitializeCluster"]
    resources = [local.cluster_arn]
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
  # Key administration, deliberately without any condition: the account root may
  # read, update and schedule deletion of this key from any principal IAM lets
  # manage KMS, so Terraform never locks itself out of the key it created.
  #
  # The list excludes kms:Sign and kms:Verify on purpose. A bare kms:* here would
  # mean any role with an IAM policy granting kms:Sign could sign with any digest
  # and algorithm, which would defeat CaSignDigestOnly below: key policy and
  # identity policy must both allow an action, so the narrower one wins.
  statement {
    sid = "AccountAdministration"
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:GetPublicKey",
      "kms:ListResourceTags",
      "kms:ListKeyPolicies",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      # Not an alias: the provider calls UpdateKeyDescription when the module's
      # name (and therefore the key description) changes.
      "kms:UpdateKeyDescription",
    ]
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
  description = "${var.name} Intermediate CA Signing Key (${var.intermediate_key_spec})"
  key_usage   = "SIGN_VERIFY"
  # `key_spec` exists in aws 5.x but is gone in 6.x; `customer_master_key_spec`
  # is accepted by both, which the declared range needs.
  customer_master_key_spec = var.intermediate_key_spec
  policy                   = data.aws_iam_policy_document.intermediate_ca_key.json
  deletion_window_in_days  = var.kms_deletion_window_in_days
  enable_key_rotation      = false # asymmetric KMS keys cannot be rotated
  multi_region             = false
  tags                     = local.tags

  # The key spec is immutable and this key signs the published chain and CRLs.
  # Replacing it would move consumers to a new signer before a new Intermediate
  # certificate exists, and destroying it would make old revocations
  # unverifiable. Roll a new generation explicitly instead of editing the spec.
  lifecycle {
    prevent_destroy = true
  }
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
  name                 = "${var.name}-ceremony-sfn"
  description          = "Drives the CloudHSM Root CA ceremony"
  assume_role_policy   = data.aws_iam_policy_document.sfn_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.tags
}

data "aws_iam_policy_document" "sfn" {
  statement {
    sid = "HsmClusterLifecycle"
    # The API is CloudHSM V2, but its IAM actions use the `cloudhsm:` prefix.
    # `cloudhsmv2:` grants nothing, so the first DescribeClusters call fails.
    # CreateHsm and InitializeCluster support the cluster resource.
    actions   = ["cloudhsm:CreateHsm", "cloudhsm:InitializeCluster"]
    resources = [local.cluster_arn]
  }

  statement {
    sid = "HsmDescribeAndDelete"
    # CreateBackup, DeleteHsm and the Describe actions support no resource-level
    # permission, so `*` is the only possible resource. CreateBackup is checked
    # before the backup ARN exists, which is why a cluster-scoped grant fails.
    actions   = ["cloudhsm:CreateBackup", "cloudhsm:DeleteHsm", "cloudhsm:DescribeClusters", "cloudhsm:DescribeBackups"]
    resources = ["*"]
  }

  # CloudHSM's CreateHsm/DeleteHsm call these EC2 actions as dependencies and
  # evaluate them with resource "*", so a statement scoped to the cluster
  # security group or an ENI ARN does not match (verified live: AccessDenied at
  # the CloudHsmV2 API for each narrower grant). AWSServiceRoleForCloudHSM does
  # not help: it is only for CloudTrail logging, and these calls use the caller's
  # identity. AWS's documented CloudHSM policy also grants them on "*".
  statement {
    sid = "HsmDependentEc2"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeTags",
      "ec2:CreateTags",
    ]
    resources = ["*"]
  }

  # CloudHSM creates its service-linked role (for logging) on first use.
  statement {
    sid       = "CreateCloudHsmServiceLinkedRole"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/cloudhsm.amazonaws.com/AWSServiceRoleForCloudHSM"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["cloudhsm.amazonaws.com"]
    }
  }

  statement {
    sid     = "RunCeremonyInstance"
    actions = ["ec2:RunInstances"]
    resources = [
      local.ceremony_ami_arn,
      local.ceremony_subnet_arn,
      local.ceremony_sg_arn,
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:network-interface/*",
    ]
  }

  statement {
    sid       = "TerminateCeremonyInstance"
    actions   = ["ec2:TerminateInstances"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
  }

  statement {
    sid     = "TagCeremonyResources"
    actions = ["ec2:CreateTags"]
    resources = [
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:network-interface/*",
    ]
  }

  statement {
    sid = "DynamoDbLease"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
    ]
    resources = [aws_dynamodb_table.ceremony_lease.arn]
  }

  # Read the owner of a conflicting lease to decide whether it is stale.
  # DescribeExecution is authorized on the *execution* ARN, not the state machine.
  statement {
    sid       = "InspectLeaseOwner"
    actions   = ["states:DescribeExecution"]
    resources = ["arn:${local.partition}:states:${local.region}:${local.account_id}:execution:${var.name}-ceremony:*"]
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
    sid     = "SendHostCommand"
    actions = ["ssm:SendCommand"]
    resources = [
      local.run_shell_doc_arn,
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*",
    ]
  }

  statement {
    sid       = "ReadHostCommand"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"] # GetCommandInvocation supports no resource-level permissions
  }

  statement {
    sid = "ReadHostInventory"
    # DescribeInstanceInformation and ListCommandInvocations support no
    # resource-level permissions.
    actions   = ["ssm:DescribeInstanceInformation", "ssm:ListCommandInvocations"]
    resources = ["*"]
  }

  # The workflow commits the verified escrow backup id before it announces the
  # chain; the host role cannot do that (it is terminated by then).
  statement {
    sid       = "RecordVerifiedBackup"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_verified_backup}"]
  }

  statement {
    sid = "Logs"
    # Log-delivery actions and DescribeLogGroups support no resource-level
    # permissions; the log group ARN cannot scope them.
    actions = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "XRay"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"] # X-Ray actions support no resource-level permissions
  }

  # The fan-out: the workflow announces the published chain and knows nothing
  # about the consumers that react to it.
  statement {
    sid       = "PublishCaReady"
    actions   = ["events:PutEvents"]
    resources = ["arn:${local.partition}:events:${local.region}:${local.account_id}:event-bus/${var.event_bus_name}"]
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

  lifecycle {
    precondition {
      condition     = var.enable_bootstrap
      error_message = "auto_bootstrap = true starts mode=BOOTSTRAP and requires enable_bootstrap = true."
    }
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      STATE_MACHINE_ARN   = aws_sfn_state_machine.ceremony.arn
      SSM_CA_BUNDLE       = local.ssm_ca_bundle_pem
      SSM_VERIFIED_BACKUP = local.ssm_verified_backup
      PKI_NAME            = var.name
      AWS_REGION          = local.region
      WAIT_TIMEOUT        = tostring(var.auto_bootstrap_timeout_seconds)
    }
    command = "${path.module}/scripts/run_ceremony_and_wait.sh"
  }

  depends_on = [
    aws_sfn_state_machine.ceremony,
    aws_cloudhsm_v2_cluster.this,
    aws_kms_key.intermediate_ca,
    aws_iam_role_policy.sfn,
    aws_ssm_parameter.ca_bundle_pem,
  ]
}
