###############################################################################
# ALB mutual TLS — the trust store and the sync Lambda
#
#   placeholder bundle   S3 object + tls self-signed cert, so CreateTrustStore
#                        succeeds on the first apply
#   sync Lambda          CAChainPublished -> install the chain and rotate the CRL
#                        rate(24 hours)   -> rotate the CRL
#
# The role is named <ca_name>-alb-mtls-sync on purpose: modules/hsm-ca's key
# policy matches signers by aws:PrincipalArn against arn:aws:iam::<account>:role/
# <ca_name>-*, so a consumer with that prefix can sign CRLs without either module
# referencing the other.
#
# hashicorp/aws has no resource for trust store revocations that expresses this
# ordering, so the CRL rotation is done through the ELBv2 API: add the new CRL,
# then remove the previous RevocationIds.
###############################################################################

locals {
  # ELBv2 caps a trust store name at 32 characters.
  trust_store_name = var.trust_store_name != "" ? var.trust_store_name : "${var.ca_contract.name}-alb-mtls"

  # Role name must keep the "<ca_name>-" prefix the key policy matches on.
  sync_lambda_name = "${var.ca_contract.name}-alb-mtls-sync"

  bundle_key = "${local.prefix}/ca_bundle.pem"
  crl_key    = "${local.prefix}/crl.pem"

  module_tag = "cloudhsmca"

  tags = merge(var.tags, {
    Module   = local.module_tag
    Ca       = var.ca_contract.name
    Consumer = "alb-mtls"
  })

  ssm_param_prefix = "arn:${var.ca_contract.partition}:ssm:${var.ca_contract.region}:${var.ca_contract.account_id}:parameter"
}

data "archive_file" "sync" {
  type        = "zip"
  output_path = "${path.module}/.terraform/archive/alb_mtls_sync.zip"

  source {
    filename = "lambda_function.py"
    content  = <<-PY
      """
      ALB mutual-TLS trust store sync: activation from CAChainPublished, then CRL
      rotation.

      Two entry points, one code path after the chain exists:

        * CAChainPublished (event.source == cloudhsmca.pki): read the published chain,
          upload it to the artifact bucket and point the trust store at that object
          version (elbv2:ModifyTrustStore), then rotate the CRL;
        * a scheduled tick: if the chain is still PENDING-CEREMONY, return
          {"skipped": "chain-not-published"} without touching S3 or ELBv2; otherwise
          rotate the CRL.

      CRL rotation is ordered so there is never a window with no CRL: sign a new one,
      AddTrustStoreRevocations with it, and only then RemoveTrustStoreRevocations on
      the previous RevocationIds. ELBv2 accepts a PEM CRL; the signature is over the
      DER TBSCertList.

      Environment:
        TRUST_STORE_ARN         the aws_lb_trust_store this consumer owns
        ARTIFACTS_BUCKET        CA artifact bucket
        BUNDLE_KEY / CRL_KEY    object keys under alb-mtls/<name>/
        CA_BUNDLE_PARAM         SSM parameter holding the published chain
        ISSUER_CERT_PARAM       SSM parameter holding the Intermediate CA PEM
        REVOKED_SERIALS_PARAM   optional SSM parameter holding revoked serials (JSON)
        KMS_KEY_ARN             Intermediate CA key (SIGN_VERIFY)
        CA_EVENT_SOURCE         event source that means "chain is ready"
        CRL_VALIDITY_DAYS       thisUpdate -> nextUpdate (default 7)
      """
      import base64
      import datetime
      import hashlib
      import json
      import logging
      import os
      import time

      import boto3

      LOG = logging.getLogger()
      LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

      TAG_INTEGER = 0x02
      TAG_BIT_STRING = 0x03
      TAG_OCTET_STRING = 0x04
      TAG_OID = 0x06
      TAG_UTC_TIME = 0x17
      TAG_SEQUENCE = 0x30
      TAG_CONTEXT_0 = 0xA0
      TAG_CONTEXT_0_PRIMITIVE = 0x80

      # KMS ECDSA signing algorithm -> (X.509 signature OID, hashlib name)
      SIG_ALGS = {
          "ECDSA_SHA_256": ("1.2.840.10045.4.3.2", "sha256"),
          "ECDSA_SHA_384": ("1.2.840.10045.4.3.3", "sha384"),
          "ECDSA_SHA_512": ("1.2.840.10045.4.3.4", "sha512"),
      }

      OID_CRL_NUMBER = "2.5.29.20"
      OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"

      REASON_CODES = {
          "unspecified": 0,
          "key_compromise": 1,
          "ca_compromise": 2,
          "affiliation_changed": 3,
          "superseded": 4,
          "cessation_of_operation": 5,
          "certificate_hold": 6,
          "privilege_withdrawn": 9,
          "aa_compromise": 10,
      }
      OID_REASON_CODE = "2.5.29.21"


      # --------------------------------------------------------------------------- #
      # minimal DER writer / reader
      # --------------------------------------------------------------------------- #

      def der_len(n):
          if n < 0x80:
              return bytes([n])
          body = n.to_bytes((n.bit_length() + 7) // 8, "big")
          return bytes([0x80 | len(body)]) + body


      def der_tlv(tag, payload):
          return bytes([tag]) + der_len(len(payload)) + payload


      def der_int(value):
          body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
          if body[0] & 0x80:
              body = b"\x00" + body
          return der_tlv(TAG_INTEGER, body)


      def der_oid(dotted):
          arcs = [int(a) for a in dotted.split(".")]
          body = bytes([arcs[0] * 40 + arcs[1]])
          for arc in arcs[2:]:
              chunk = bytearray([arc & 0x7F])
              arc >>= 7
              while arc:
                  chunk.insert(0, 0x80 | (arc & 0x7F))
                  arc >>= 7
              body += bytes(chunk)
          return der_tlv(TAG_OID, body)


      def der_time(moment):
          # UTCTime covers 1950-2049, which is the whole lifetime of any CRL here.
          return der_tlv(TAG_UTC_TIME, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


      def der_extension(oid, critical, value):
          body = der_oid(oid)
          if critical:
              body += der_tlv(0x01, b"\xff")
          return der_tlv(TAG_SEQUENCE, body + der_tlv(TAG_OCTET_STRING, value))


      def read_tlv(buf, off):
          tag = buf[off]
          first = buf[off + 1]
          if first < 0x80:
              return tag, 2, first, 2 + first
          count = first & 0x7F
          length = int.from_bytes(buf[off + 2:off + 2 + count], "big")
          header = 2 + count
          return tag, header, length, header + length


      def children(element):
          """(tag, raw, content) for each direct child of one DER element."""
          tag, hlen, clen, total = read_tlv(element, 0)
          if total != len(element):
              raise ValueError("DER: trailing bytes after element")
          out = []
          off = hlen
          end = hlen + clen
          while off < end:
              ctag, chlen, cclen, ctotal = read_tlv(element, off)
              out.append((ctag, element[off:off + ctotal],
                          element[off + chlen:off + chlen + cclen]))
              off += ctotal
          return out


      def pem_to_der(pem):
          if isinstance(pem, bytes):
              pem = pem.decode("ascii", "replace")
          body = "".join(
              line for line in pem.strip().splitlines() if "-----" not in line
          )
          return base64.b64decode(body)


      def as_der(blob):
          """ImportCrl/GetCrl speak PEM; accept either form and compare DER."""
          if isinstance(blob, str):
              blob = blob.encode("ascii", "replace")
          stripped = blob.lstrip()
          if stripped.startswith(b"-----BEGIN"):
              return pem_to_der(stripped)
          return blob


      # --------------------------------------------------------------------------- #
      # issuer identity, lifted straight out of the CA certificate
      # --------------------------------------------------------------------------- #

      def issuer_identity(cert_der):
          """
          Return (subject_name_der, authority_key_identifier) from a certificate.

          TBSCertificate ::= SEQUENCE { [0] version, serial, signature, issuer,
                                        validity, subject, subjectPublicKeyInfo, ... }
          The CRL's `issuer` field must be the CRL signer's SUBJECT, and its AKI is
          method 1 (SHA-1 over the subjectPublicKey BIT STRING contents), which is
          what this module's SubjectKeyIdentifier extension also used.
          """
          tbs = children(cert_der)[0][1]
          fields = children(tbs)
          index = 1 if fields[0][0] == TAG_CONTEXT_0 else 0
          # serial, signature, issuer, validity, subject, spki
          subject = fields[index + 4][1]
          spki = fields[index + 5][1]
          _tag, _raw, bit_content = children(spki)[1]
          key_bits = bit_content[1:]  # drop the "unused bits" octet
          return subject, hashlib.sha1(key_bits).digest()


      # --------------------------------------------------------------------------- #
      # revocation list + signing
      # --------------------------------------------------------------------------- #

      def parse_iso(value):
          text = str(value).replace("Z", "+00:00")
          try:
              parsed = datetime.datetime.fromisoformat(text)
          except ValueError:
              raise ValueError("revoked_at is not ISO-8601: %r" % value)
          return parsed if parsed.tzinfo else parsed.replace(
              tzinfo=datetime.timezone.utc)


      def build_crl(issuer_subject_der, akid, revoked, crl_number, validity_days):
          now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
          next_update = now + datetime.timedelta(days=validity_days)

          revoked_seq = b""
          for entry in revoked:
              entry_body = der_int(entry["serial"]) + der_time(entry["when"])
              reason = entry.get("reason")
              if reason:
                  code = REASON_CODES.get(str(reason).lower())
                  if code is None:
                      raise ValueError("unknown revocation reason: %s" % reason)
                  entry_body += der_tlv(TAG_SEQUENCE, der_extension(
                      OID_REASON_CODE, False, der_tlv(0x0A, bytes([code]))))
              revoked_seq += der_tlv(TAG_SEQUENCE, entry_body)

          extensions = der_extension(
              OID_CRL_NUMBER, False, der_int(crl_number)
          ) + der_extension(
              OID_AUTHORITY_KEY_IDENTIFIER, False,
              der_tlv(TAG_SEQUENCE, der_tlv(TAG_CONTEXT_0_PRIMITIVE, akid)),
          )

          return now, next_update, revoked_seq, extensions


      def sign_crl(kms, key_arn, tbs, sig_alg_name):
          oid, hash_name = SIG_ALGS[sig_alg_name]
          digest = hashlib.new(hash_name, tbs).digest()
          signature = kms.sign(
              KeyId=key_arn,
              Message=digest,
              MessageType="DIGEST",
              SigningAlgorithm=sig_alg_name,
          )["Signature"]
          alg_id = der_tlv(TAG_SEQUENCE, der_oid(oid))
          return der_tlv(TAG_SEQUENCE, tbs + alg_id + der_tlv(
              TAG_BIT_STRING, b"\x00" + signature))


      def pem_wrap(der, label):
          body = base64.b64encode(der).decode("ascii")
          lines = [body[i:i + 64] for i in range(0, len(body), 64)]
          return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
              label, "\n".join(lines), label)


      # --------------------------------------------------------------------------- #
      # environment helpers
      # --------------------------------------------------------------------------- #

      def read_parameter(ssm, name):
          """SSM value, or None when the parameter does not exist yet."""
          if not name:
              return None
          try:
              return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
          except ssm.exceptions.ParameterNotFound:
              return None


      def load_revocations_ssm(ssm, param):
          """Revoked serials from an SSM parameter, in build_crl's shape."""
          raw = read_parameter(ssm, param)
          if not raw:
              LOG.warning("no revocation list at %s: issuing an empty CRL", param or "<unset>")
              return []
          payload = json.loads(raw)
          entries = payload.get("revoked", payload) if isinstance(payload, dict) else payload
          revoked = []
          for entry in entries:
              if isinstance(entry, dict):
                  serial = entry["serial"]
                  when = entry.get("revoked_at")
                  reason = entry.get("reason")
              else:
                  serial, when, reason = entry, None, None
              revoked.append({
                  "serial": int(str(serial), 16) if str(serial).lower().startswith("0x")
                  else int(serial),
                  "when": parse_iso(when) if when else (
                      datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(days=1)),
                  "reason": reason,
              })
          LOG.info("loaded %d revoked serials from %s", len(revoked), param)
          return revoked


      def put_versioned(s3, bucket, key, body, content_type):
          """Upload and return the VersionId the next API call has to reference."""
          return s3.put_object(
              Bucket=bucket,
              Key=key,
              Body=body,
              ContentType=content_type,
              ServerSideEncryption="AES256",
          )["VersionId"]


      # --------------------------------------------------------------------------- #
      # handler
      # --------------------------------------------------------------------------- #

      def handler(event, context):
          event = event or {}
          activation = event.get("source") == os.environ.get(
              "CA_EVENT_SOURCE", "cloudhsmca.pki")

          bucket = os.environ["ARTIFACTS_BUCKET"]
          bundle_key = os.environ["BUNDLE_KEY"]
          crl_key = os.environ["CRL_KEY"]
          bundle_param = os.environ["CA_BUNDLE_PARAM"]
          issuer_param = os.environ["ISSUER_CERT_PARAM"]
          revocations_param = os.environ.get("REVOKED_SERIALS_PARAM", "")
          trust_store_arn = os.environ["TRUST_STORE_ARN"]
          key_arn = os.environ["KMS_KEY_ARN"]
          validity_days = int(os.environ.get("CRL_VALIDITY_DAYS", "7"))

          ssm = boto3.client("ssm")
          kms = boto3.client("kms")
          s3 = boto3.client("s3")
          elbv2 = boto3.client("elbv2")

          bundle = read_parameter(ssm, bundle_param)
          chain_ready = bool(bundle) and bundle.count("BEGIN CERTIFICATE") >= 2 \
              and "PENDING-CEREMONY" not in bundle

          if activation and not chain_ready:
              raise RuntimeError(
                  "CAChainPublished arrived but %s holds no usable chain" % bundle_param)
          if not activation and not chain_ready:
              LOG.info("chain not published at %s: skipping this tick", bundle_param)
              return {"ok": True, "skipped": "chain-not-published",
                      "reason": event.get("reason", "scheduled")}

          result = {"ok": True, "activated": activation}

          if activation:
              # The bundle is a file in the bucket first; the trust store then points at
              # that exact object version, so a concurrent overwrite cannot half-apply.
              version_id = put_versioned(s3, bucket, bundle_key,
                                         bundle.encode("ascii"), "application/x-pem-file")
              elbv2.modify_trust_store(
                  TrustStoreArn=trust_store_arn,
                  CaCertificatesBundleS3Bucket=bucket,
                  CaCertificatesBundleS3Key=bundle_key,
                  CaCertificatesBundleS3ObjectVersion=version_id,
              )
              result["bundleVersionId"] = version_id
              LOG.info("trust store bundle updated to version %s (%d certificates)",
                       version_id, bundle.count("BEGIN CERTIFICATE"))

          # ---- CRL: sign, upload, add, then remove the old one -------------------
          issuer_pem = read_parameter(ssm, issuer_param)
          if not issuer_pem:
              raise RuntimeError("%s is empty: cannot build a CRL without the issuer"
                                 % issuer_param)
          subject_der, akid = issuer_identity(pem_to_der(issuer_pem))

          public_key = kms.get_public_key(KeyId=key_arn)
          algorithms = public_key.get("SigningAlgorithms") or []
          sig_alg_name = next((a for a in ("ECDSA_SHA_384", "ECDSA_SHA_256",
                                           "ECDSA_SHA_512") if a in algorithms), None)
          if sig_alg_name is None:
              raise RuntimeError("KMS key exposes no supported ECDSA signing algorithm: %s"
                                 % algorithms)

          revoked = load_revocations_ssm(ssm, revocations_param)
          crl_number = int(time.time())
          now, next_update, revoked_seq, extensions = build_crl(
              subject_der, akid, revoked, crl_number, validity_days)

          tbs = der_tlv(TAG_SEQUENCE,
                        der_int(1)                                   # v2
                        + der_tlv(TAG_SEQUENCE, der_oid(SIG_ALGS[sig_alg_name][0]))
                        + subject_der                                # issuer
                        + der_time(now)
                        + der_time(next_update)
                        + (der_tlv(TAG_SEQUENCE, revoked_seq) if revoked_seq else b"")
                        + der_tlv(TAG_CONTEXT_0, der_tlv(TAG_SEQUENCE, extensions)))

          crl_der = sign_crl(kms, key_arn, tbs, sig_alg_name)
          crl_pem = pem_wrap(crl_der, "X509 CRL")
          crl_version = put_versioned(s3, bucket, crl_key,
                                      crl_pem.encode("ascii"), "application/x-pem-file")

          existing = elbv2.describe_trust_store_revocations(
              TrustStoreArn=trust_store_arn).get("TrustStoreRevocations", [])
          previous = [r["RevocationId"] for r in existing
                      if r.get("RevocationType", "CRL") == "CRL"]

          added = elbv2.add_trust_store_revocations(
              TrustStoreArn=trust_store_arn,
              Revocations=[{
                  "RevocationType": "CRL",
                  "RevocationS3Bucket": bucket,
                  "RevocationS3Key": crl_key,
                  "RevocationS3ObjectVersion": crl_version,
              }],
          ).get("TrustStoreRevocations", [])
          new_ids = [r["RevocationId"] for r in added]

          # Only now is the old CRL redundant; removing it first would leave a window
          # in which the trust store has no revocation data at all.
          stale = [rid for rid in previous if rid not in new_ids]
          if stale:
              elbv2.remove_trust_store_revocations(
                  TrustStoreArn=trust_store_arn, RevocationIds=stale)

          result.update({
              "crlVersionId": crl_version,
              "revocationIds": new_ids,
              "replacedRevocations": stale,
              "revokedSerials": len(revoked),
              "nextUpdate": next_update.isoformat(),
              "sha256": hashlib.sha256(crl_der).hexdigest(),
          })
          LOG.info("CRL %s imported (%d revoked, nextUpdate=%s), replaced %s",
                   new_ids, len(revoked), next_update.isoformat(), stale)
          return result
    PY
  }
}

resource "aws_cloudwatch_log_group" "sync" {
  name              = "/aws/lambda/${local.sync_lambda_name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

data "aws_iam_policy_document" "sync_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sync" {
  name               = local.sync_lambda_name
  description        = "Keeps the ${local.trust_store_name} trust store and its CRL in step with the CA"
  assume_role_policy = data.aws_iam_policy_document.sync_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "sync" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.sync.arn}:*"]
  }

  statement {
    sid     = "ReadChainIssuerAndRevocations"
    actions = ["ssm:GetParameter"]
    resources = compact([
      "${local.ssm_param_prefix}${var.ca_contract.ca_bundle_ssm_param}",
      "${local.ssm_param_prefix}${var.ca_contract.intermediate_ca_ssm_param}",
      var.revoked_serials_ssm_param == "" ? "" : "${local.ssm_param_prefix}${var.revoked_serials_ssm_param}",
    ])
  }

  statement {
    sid       = "WriteBundleAndCrl"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.ca_contract.artifacts_bucket_arn}/${local.prefix}/*"]
  }

  statement {
    sid = "TrustStoreRevocations"
    actions = [
      "elasticloadbalancing:DescribeTrustStores",
      "elasticloadbalancing:DescribeTrustStoreRevocations",
      "elasticloadbalancing:ModifyTrustStore",
      "elasticloadbalancing:AddTrustStoreRevocations",
      "elasticloadbalancing:RemoveTrustStoreRevocations",
    ]
    resources = [aws_lb_trust_store.this.arn]
  }

  # Digest-only signing, in its own statement: kms:MessageType and
  # kms:SigningAlgorithm do not exist on a GetPublicKey request, so folding them
  # together would deny the read.
  statement {
    sid       = "SignWithIntermediateCa"
    actions   = ["kms:Sign"]
    resources = [var.ca_contract.intermediate_kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = [var.ca_contract.signing_algorithm]
    }
  }

  statement {
    sid       = "ReadIntermediateCaKey"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = [var.ca_contract.intermediate_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "sync" {
  name   = "alb-mtls-sync"
  role   = aws_iam_role.sync.id
  policy = data.aws_iam_policy_document.sync.json
}

resource "aws_lambda_function" "sync" {
  function_name = local.sync_lambda_name
  description   = "Installs the ${var.ca_contract.name} chain into ${local.trust_store_name} and rotates its CRL"
  role          = aws_iam_role.sync.arn

  filename         = data.archive_file.sync.output_path
  source_code_hash = data.archive_file.sync.output_base64sha256
  handler          = "lambda_function.handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 120
  memory_size      = 256

  # One CRL owner: concurrent runs would add and remove revocations in an
  # unpredictable order.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      TRUST_STORE_ARN       = aws_lb_trust_store.this.arn
      ARTIFACTS_BUCKET      = var.ca_contract.artifacts_bucket
      BUNDLE_KEY            = local.bundle_key
      CRL_KEY               = local.crl_key
      CA_BUNDLE_PARAM       = var.ca_contract.ca_bundle_ssm_param
      ISSUER_CERT_PARAM     = var.ca_contract.intermediate_ca_ssm_param
      REVOKED_SERIALS_PARAM = var.revoked_serials_ssm_param
      KMS_KEY_ARN           = var.ca_contract.intermediate_kms_key_arn
      CA_EVENT_SOURCE       = var.ca_contract.event_source
      CRL_VALIDITY_DAYS     = tostring(var.crl_validity_days)
      LOG_LEVEL             = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.sync,
    aws_iam_role_policy.sync,
  ]

  tags = local.tags
}

###############################################################################
# Trigger 1: the CA published its chain
###############################################################################

resource "aws_cloudwatch_event_rule" "ca_chain_published" {
  name           = "${var.ca_contract.name}-alb-mtls-ca-published"
  description    = "Install the ${var.ca_contract.name} chain into ${local.trust_store_name}"
  event_bus_name = var.ca_contract.event_bus_name

  event_pattern = jsonencode({
    source        = [var.ca_contract.event_source]
    "detail-type" = [var.ca_contract.event_detail_type]
    detail = {
      ca_name = [var.ca_contract.name]
    }
  })

  tags = local.tags
}

# No input transformer: the handler reads event.source to tell activation from a
# scheduled tick.
resource "aws_cloudwatch_event_target" "ca_chain_published" {
  rule           = aws_cloudwatch_event_rule.ca_chain_published.name
  event_bus_name = var.ca_contract.event_bus_name
  target_id      = "alb-mtls-activation"
  arn            = aws_lambda_function.sync.arn
}

resource "aws_lambda_permission" "ca_chain_published" {
  statement_id  = "AllowEventBridgeCaChainPublished"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ca_chain_published.arn
}

###############################################################################
# Trigger 2: routine CRL rotation
#
# A CRL whose nextUpdate has passed stops revoking anything, so this is not
# optional; the activation path only runs once per ceremony.
###############################################################################

resource "aws_cloudwatch_event_rule" "crl_refresh" {
  name                = "${var.ca_contract.name}-alb-mtls-crl-refresh"
  description         = "Rotate the ${local.trust_store_name} CRL"
  schedule_expression = var.sync_schedule
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "crl_refresh" {
  rule      = aws_cloudwatch_event_rule.crl_refresh.name
  target_id = "alb-mtls-crl-refresh"
  arn       = aws_lambda_function.sync.arn

  input = jsonencode({ reason = "scheduled-refresh" })
}

resource "aws_lambda_permission" "crl_refresh" {
  statement_id  = "AllowEventBridgeCrlRefresh"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crl_refresh.arn
}
