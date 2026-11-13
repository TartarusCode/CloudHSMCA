###############################################################################
# Phase 1 — the Root CA ceremony (and the only place an HSM is ever billed)
#
#   aws_cloudhsm_v2_cluster  hsm2m.medium, FIPS mode  -> FIPS 140-3 Level 3
#   aws_cloudhsm_v2_hsm      exactly one, phase 1 only -> ~$1.50/hr, terminated
#                            by the phase 2 apply; AWS keeps the encrypted
#                            cluster backup (that backup IS the key escrow)
#   aws_instance.ceremony    AL2023, IMDSv2 only, no public IP, no inbound
#                            rules, reachable only through SSM Session Manager
#
# The host receives one JSON document of facts and pulls scripts/kms_ca_tool.py
# plus the two rendered OpenSSL profiles from the artifact bucket, so nothing
# in user data can drift from the repository copy of the tooling.
###############################################################################

locals {
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
  hsm_public_key_der = "/opt/pki/root_ca_pub.der"

  ceremony_config = {
    name                 = var.name
    region               = local.region
    cluster_id           = aws_cloudhsm_v2_cluster.this.cluster_id
    hsm_ip               = var.ceremony_mode ? aws_cloudhsm_v2_hsm.ceremony[0].ip_address : ""
    bucket               = aws_s3_bucket.artifacts.id
    kms_key_arn          = aws_kms_key.intermediate_ca.arn
    root_curve           = var.root_key_curve
    root_digest          = local.root_digest
    root_label           = local.hsm_root_key_label
    public_key_der       = local.hsm_public_key_der
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
    cu_username          = "pki-cu"
    cloudhsm_cli_rpm     = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"
  }
}

###############################################################################
# Cluster
###############################################################################

resource "aws_cloudhsm_v2_cluster" "this" {
  hsm_type   = "hsm2m.medium"
  mode       = "FIPS"
  subnet_ids = var.private_subnet_ids
  tags       = merge(local.tags, { Name = "${var.name}-hsm-cluster" })
}

resource "aws_cloudhsm_v2_hsm" "ceremony" {
  count = var.ceremony_mode ? 1 : 0

  cluster_id = aws_cloudhsm_v2_cluster.this.cluster_id
  subnet_id  = var.private_subnet_ids[0]

  depends_on = [aws_cloudhsm_v2_cluster.this]
}

###############################################################################
# Network: egress-only for the ceremony host.
#
# The cluster's own security group already allows 2223-2225 between members, so
# the instance is placed in it as well (the documented way to reach an HSM ENI)
# and this group contributes nothing inbound.
###############################################################################

resource "aws_security_group" "ceremony" {
  count = var.ceremony_mode ? 1 : 0

  name_prefix = "${var.name}-ceremony-"
  description = "Egress-only security group for the ephemeral PKI ceremony host"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-ceremony" })

  # No ingress blocks at all: access is exclusively via SSM Session Manager.

  egress {
    description = "AWS APIs (SSM, S3, KMS, CloudHSM control plane)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "CloudHSM customer HSM ports - to the cluster security group only"
    from_port       = 2223
    to_port         = 2225
    protocol        = "tcp"
    self            = false
    security_groups = [aws_cloudhsm_v2_cluster.this.security_group_id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# Ceremony host IAM
###############################################################################

data "aws_iam_policy_document" "ceremony_host_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ceremony_host" {
  count = var.ceremony_mode ? 1 : 0

  name                 = "${var.name}-ceremony-host"
  description          = "Ephemeral host that runs the CloudHSM Root CA ceremony"
  assume_role_policy   = data.aws_iam_policy_document.ceremony_host_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "ceremony_ssm_core" {
  count      = var.ceremony_mode ? 1 : 0
  role       = aws_iam_role.ceremony_host[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "ceremony_host" {
  statement {
    sid = "ReadCeremonyParameters"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_hsm_admin_password}",
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_hsm_cu_password}",
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_root_ca_pem}",
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_intermediate_ca_pem}",
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_ca_bundle_pem}",
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.ssm_ceremony_state}",
    ]
  }

  statement {
    sid       = "WriteCeremonyOutput"
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

  statement {
    sid       = "ReadCeremonyScripts"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/scripts/*"]
  }

  statement {
    sid       = "WriteCertificates"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/certs/*"]
  }

  statement {
    sid       = "DescribeHsmCluster"
    actions   = ["cloudhsm:DescribeClusters", "cloudhsm:DescribeBackups"]
    resources = ["*"]
  }

  statement {
    sid       = "CeremonyLogs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/ec2/${var.name}-ceremony*"]
  }
}

resource "aws_iam_role_policy" "ceremony_host" {
  count  = var.ceremony_mode ? 1 : 0
  name   = "ceremony-host"
  role   = aws_iam_role.ceremony_host[0].id
  policy = data.aws_iam_policy_document.ceremony_host.json
}

resource "aws_iam_instance_profile" "ceremony_host" {
  count = var.ceremony_mode ? 1 : 0
  name  = "${var.name}-ceremony-host"
  role  = aws_iam_role.ceremony_host[0].name
  tags  = local.tags
}

###############################################################################
# Rendered profiles + tooling, published to the artifact bucket
###############################################################################

resource "aws_s3_object" "kms_ca_tool" {
  count = var.ceremony_mode ? 1 : 0

  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/kms_ca_tool.py"
  content                = file("${path.module}/scripts/kms_ca_tool.py")
  content_type           = "text/x-python"
  etag                   = filemd5("${path.module}/scripts/kms_ca_tool.py")
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "root_ca_cnf" {
  count = var.ceremony_mode ? 1 : 0

  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/root_ca.cnf"
  content                = templatefile("${path.module}/scripts/root_ca.cnf.tftpl", local.cnf_vars)
  content_type           = "text/plain"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

resource "aws_s3_object" "intermediate_ca_cnf" {
  count = var.ceremony_mode ? 1 : 0

  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "scripts/intermediate_ca.cnf"
  content                = templatefile("${path.module}/scripts/intermediate_ca.cnf.tftpl", local.cnf_vars)
  content_type           = "text/plain"
  server_side_encryption = "AES256"
  tags                   = local.tags
}

###############################################################################
# Ephemeral ceremony host
###############################################################################

data "aws_ami" "al2023" {
  count = var.ceremony_mode ? 1 : 0

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

resource "aws_instance" "ceremony" {
  count = var.ceremony_mode ? 1 : 0

  ami                         = data.aws_ami.al2023[0].id
  instance_type               = var.ceremony_instance_type
  subnet_id                   = var.private_subnet_ids[0]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ceremony_host[0].name

  # The cluster security group provides HSM reachability; this one is egress-only.
  vpc_security_group_ids = [
    aws_cloudhsm_v2_cluster.this.security_group_id,
    aws_security_group.ceremony[0].id,
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/scripts/hsm_ceremony.sh.tftpl", {
    ceremony_config = jsonencode(local.ceremony_config)
  })

  tags = merge(local.tags, { Name = "${var.name}-ceremony-host" })

  depends_on = [
    aws_cloudhsm_v2_hsm.ceremony,
    aws_iam_role_policy.ceremony_host,
    aws_s3_object.kms_ca_tool,
    aws_s3_object.root_ca_cnf,
    aws_s3_object.intermediate_ca_cnf,
  ]
}
