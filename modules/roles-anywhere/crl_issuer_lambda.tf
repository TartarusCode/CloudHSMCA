###############################################################################
# Activation + CRL refresh — one Lambda, two triggers
#
#   cloudhsmca.pki / CAChainPublished  ->  install the chain, enable the anchor,
#                                          import the first CRL
#   rate(24 hours)                     ->  re-sign and re-import the CRL
#
# It is the consumer's only coupling to the PKI engine: one event contract, one
# shared signing key, no Terraform resource crossing the module boundary. The
# scheduled tick on an unpublished CA is a no-op (the bundle still reads
# PENDING-CEREMONY), and the activation tick without a bundle is a hard failure,
# because that combination means the workflow published an event with no chain.
#
# hashicorp/aws has no aws_rolesanywhere_crl resource (5.x and 6.x schemas both
# checked), so nothing in Terraform holds CRL state.
#
# The handler is stdlib-only on purpose (the Python runtime has no
# `cryptography`): DER is encoded by hand, the signature is over the DER
# TBSCertList, and the API gets PEM as documented. After ImportCrl the stored
# bytes are read back with GetCrl and compared to what was signed.
###############################################################################

locals {
  # The rest of the shared locals (name, tags, the SSM parameter ARNs) are
  # declared in roles_anywhere.tf; a module may only define each one once.
  crl_lambda_name = "${local.name}-crl-issuer"
}

data "archive_file" "crl_issuer" {
  type        = "zip"
  output_path = "${path.module}/.terraform/archive/crl_issuer.zip"

  source {
    filename = "lambda_function.py"
    content  = <<-PY
      """
      IAM Roles Anywhere CRL issuer.

      Builds an X.509 v2 Certificate Revocation List for the KMS-backed Intermediate
      CA, signs the TBSCertList with kms.sign(MessageType='DIGEST'), and imports it
      into the trust anchor with rolesanywhere:ImportCrl. The signature is over DER,
      which is what X.509 mandates; the ImportCrl API itself takes the CRL **in PEM**
      (API reference: "a CRL must be in PEM format"), so the DER is wrapped before it
      is sent.

      Deliberately stdlib-only: the Lambda runtime does not ship `cryptography`, so
      the DER for TBSCertList is encoded (and the issuer name / authority key
      identifier are lifted out of the CA certificate) by hand. The signed bytes are
      assembled exactly once and never re-encoded, then AWS is asked for the stored
      CRL back so the byte-for-byte round trip is proved at run time.

      Two entry points, one code path after the chain is available:

        * an EventBridge envelope (source == CA_EVENT_SOURCE): read the chain,
          UpdateTrustAnchor + EnableTrustAnchor, then import a CRL;
        * a scheduled tick: if the chain is still PENDING-CEREMONY, skip; else
          import a refreshed CRL.

      Environment:
        TRUST_ANCHOR_ARN        trust anchor to activate and import against
        TRUST_ANCHOR_ID         its id, for UpdateTrustAnchor/EnableTrustAnchor
        CA_BUNDLE_PARAM         SSM parameter holding the published chain
        CA_EVENT_SOURCE         event source that means "chain is ready"
        ISSUER_CERT_PARAM       SSM parameter holding the Intermediate CA PEM
        KMS_KEY_ARN             Intermediate CA key (SIGN_VERIFY)
        REVOCATIONS_S3_URI      s3://bucket/key JSON list of revoked serials
        CRL_OUTPUT_PREFIX       s3://bucket/prefix for the DER/PEM copies
        CRL_VALIDITY_DAYS       thisUpdate -> nextUpdate (default 7)
        CRL_NAME_PREFIX         ImportCrl name prefix (default crl)
      """

      import base64
      import datetime
      import hashlib
      import json
      import logging
      import os
      import time
      import urllib.parse

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


      def load_revocations(s3, uri):
          if not uri:
              LOG.warning("REVOCATIONS_S3_URI is unset: issuing an empty CRL")
              return []
          parsed = urllib.parse.urlparse(uri)
          bucket = parsed.netloc
          key = parsed.path.lstrip("/")
          try:
              body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
          except s3.exceptions.NoSuchKey:
              LOG.warning("no revocation list at %s: issuing an empty CRL", uri)
              return []
          payload = json.loads(body)
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
          LOG.info("loaded %d revoked serials from %s", len(revoked), uri)
          return revoked


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
      # handler
      # --------------------------------------------------------------------------- #

      def handler(event, context):
          trust_anchor_arn = os.environ.get("TRUST_ANCHOR_ARN", "")
          issuer_param = os.environ["ISSUER_CERT_PARAM"]
          key_arn = os.environ["KMS_KEY_ARN"]
          validity_days = int(os.environ.get("CRL_VALIDITY_DAYS", "7"))
          name_prefix = os.environ.get("CRL_NAME_PREFIX", "crl")
          output_prefix = os.environ.get("CRL_OUTPUT_PREFIX", "")

          if not trust_anchor_arn:
              raise RuntimeError(
                  "TRUST_ANCHOR_ARN is empty: the module did not wire the trust anchor")

          ssm = boto3.client("ssm")
          kms = boto3.client("kms")
          s3 = boto3.client("s3")
          rolesanywhere = boto3.client("rolesanywhere")

          # ---- activation vs refresh --------------------------------------
          event = event or {}
          activation = event.get("source") == os.environ.get(
              "CA_EVENT_SOURCE", "cloudhsmca.pki")
          bundle_param = os.environ.get("CA_BUNDLE_PARAM", "")

          bundle = None
          if bundle_param:
              try:
                  bundle = ssm.get_parameter(Name=bundle_param)["Parameter"]["Value"]
              except ssm.exceptions.ParameterNotFound:
                  bundle = None
          chain_ready = bool(bundle) and "BEGIN CERTIFICATE" in bundle \
              and "PENDING-CEREMONY" not in bundle

          if activation:
              # An event without a chain means the workflow published before it
              # wrote SSM: fail loudly, never enable an anchor without a bundle.
              if not chain_ready:
                  raise RuntimeError(
                      "CAChainPublished arrived but %s holds no usable chain"
                      % bundle_param)
              trust_anchor_id = os.environ["TRUST_ANCHOR_ID"]
              rolesanywhere.update_trust_anchor(
                  trustAnchorId=trust_anchor_id,
                  source={
                      "sourceType": "CERTIFICATE_BUNDLE",
                      "sourceData": {"x509CertificateData": bundle},
                  })
              rolesanywhere.enable_trust_anchor(trustAnchorId=trust_anchor_id)
              LOG.info("trust anchor %s installed %d certificates and enabled",
                       trust_anchor_id, bundle.count("BEGIN CERTIFICATE"))
          elif bundle_param and not chain_ready:
              # A scheduled tick before the first ceremony: nothing to revoke
              # against yet, and an imported CRL would be useless anyway.
              LOG.info("chain not published at %s: skipping this tick", bundle_param)
              return {"ok": True, "skipped": "chain-not-published",
                      "reason": event.get("reason", "scheduled")}

          issuer_der = pem_to_der(ssm.get_parameter(Name=issuer_param)["Parameter"]["Value"])
          subject_der, akid = issuer_identity(issuer_der)

          public_key = kms.get_public_key(KeyId=key_arn)
          algorithms = public_key.get("SigningAlgorithms") or []
          sig_alg_name = next((a for a in ("ECDSA_SHA_384", "ECDSA_SHA_256",
                                           "ECDSA_SHA_512") if a in algorithms), None)
          if sig_alg_name is None:
              raise RuntimeError("KMS key exposes no supported ECDSA signing algorithm: %s"
                                 % algorithms)

          revoked = load_revocations(s3, os.environ.get("REVOCATIONS_S3_URI", ""))
          if not revoked:
              # Roles Anywhere refuses a CRL that revokes nothing:
              #   ValidationException: At least one of the included CRLs doesn't
              #   include a revoked certificate.
              # Nothing to import — but a CRL imported earlier is still active and
              # would keep revoking serials the list no longer names, so retire
              # every enabled CRL for this anchor. ListCrls is account-wide, so
              # the anchor is matched on trustAnchorArn.
              retired = []
              for existing in rolesanywhere.list_crls().get("crls", []):
                  if existing.get("trustAnchorArn") != trust_anchor_arn:
                      continue
                  if not existing.get("enabled"):
                      continue
                  rolesanywhere.disable_crl(crlId=existing["crlId"])
                  retired.append(existing["crlId"])
              LOG.info("no revoked serials: nothing to import, retired %d CRL(s) %s",
                       len(retired), retired)
              return {"ok": True, "skipped": "no-revocations",
                      "disabledCrls": retired,
                      "reason": event.get("reason", "scheduled")}

          crl_number = int(time.time())
          now, next_update, revoked_seq, extensions = build_crl(
              subject_der, akid, revoked, crl_number, validity_days)

          tbs = der_tlv(TAG_SEQUENCE,
                        der_int(1)                                   # v2
                        + der_tlv(TAG_SEQUENCE, der_oid(SIG_ALGS[sig_alg_name][0]))
                        + subject_der                                 # issuer
                        + der_time(now)
                        + der_time(next_update)
                        # revokedCertificates SEQUENCE OF is optional: omit entirely
                        # when nothing is revoked, never emit a bare empty SEQUENCE.
                        + (der_tlv(TAG_SEQUENCE, revoked_seq) if revoked_seq else b"")
                        + der_tlv(TAG_CONTEXT_0, der_tlv(TAG_SEQUENCE, extensions)))

          crl_der = sign_crl(kms, key_arn, tbs, sig_alg_name)
          crl_pem = pem_wrap(crl_der, "X509 CRL")
          digest_sha256 = hashlib.sha256(crl_der).hexdigest()

          name = "%s-%s" % (name_prefix, now.strftime("%Y%m%dT%H%M%SZ"))
          imported = rolesanywhere.import_crl(
              name=name,
              # Documented format for ImportCrl: "a CRL must be in PEM format".
              crlData=crl_pem.encode("ascii"),
              trustAnchorArn=trust_anchor_arn,
              enabled=True,
          )["crl"]
          crl_id = imported["crlId"]

          # Prove the round trip: AWS must return exactly the CRL we signed.
          stored = rolesanywhere.get_crl(crlId=crl_id)["crl"]
          stored_sha256 = hashlib.sha256(as_der(stored["crlData"])).hexdigest()
          if stored_sha256 != digest_sha256:
              raise RuntimeError(
                  "stored CRL digest %s does not match the signed digest %s"
                  % (stored_sha256, digest_sha256))
          if not stored.get("enabled"):
              raise RuntimeError("imported CRL %s is not enabled" % crl_id)

          if output_prefix:
              parsed = urllib.parse.urlparse(output_prefix)
              base = parsed.path.lstrip("/")
              s3.put_object(Bucket=parsed.netloc, Key="%s/%s.der" % (base, name),
                            Body=crl_der, ContentType="application/pkix-crl")
              s3.put_object(Bucket=parsed.netloc, Key="%s/%s.pem" % (base, name),
                            Body=crl_pem.encode("ascii"))
              s3.put_object(Bucket=parsed.netloc, Key="%s/latest.der" % base,
                            Body=crl_der, ContentType="application/pkix-crl")
              s3.put_object(Bucket=parsed.netloc, Key="%s/latest.pem" % base,
                            Body=crl_pem.encode("ascii"))

          LOG.info("imported CRL %s (%s) revoked=%d next_update=%s sha256=%s",
                   crl_id, name, len(revoked), next_update.isoformat(), digest_sha256)

          return {
              "ok": True,
              "activated": activation,
              "crlId": crl_id,
              "crlArn": imported.get("crlArn"),
              "name": name,
              "revoked": len(revoked),
              "crlNumber": crl_number,
              "nextUpdate": next_update.isoformat(),
              "sha256": digest_sha256,
              "signingAlgorithm": sig_alg_name,
          }
      PY
  }
}


###############################################################################
# The Lambda and its role
###############################################################################

resource "aws_cloudwatch_log_group" "crl_issuer" {
  name              = "/aws/lambda/${local.crl_lambda_name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

data "aws_iam_policy_document" "crl_issuer_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "crl_issuer" {
  name               = local.crl_lambda_name
  description        = "Activates the Roles Anywhere trust anchor and keeps its CRL fresh"
  assume_role_policy = data.aws_iam_policy_document.crl_issuer_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "crl_issuer" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.crl_issuer.arn}:*"]
  }

  # Both SSM reads: the published chain (activation) and the issuer certificate
  # (every CRL, since the TBSCertList embeds the issuer name and key id).
  statement {
    sid       = "ReadChainAndIssuer"
    actions   = ["ssm:GetParameter"]
    resources = [local.ca_bundle_param_arn, local.issuer_param_arn]
  }

  statement {
    sid = "ActivateTrustAnchor"
    actions = [
      "rolesanywhere:UpdateTrustAnchor",
      "rolesanywhere:EnableTrustAnchor",
    ]
    resources = [aws_rolesanywhere_trust_anchor.this.arn]
  }

  statement {
    sid = "ImportCrl"
    actions = [
      "rolesanywhere:ImportCrl",
      "rolesanywhere:GetCrl",
      "rolesanywhere:EnableCrl",
      "rolesanywhere:DisableCrl",
    ]
    resources = [
      "arn:${var.ca_contract.partition}:rolesanywhere:${var.ca_contract.region}:${var.ca_contract.account_id}:trust-anchor/*",
      "arn:${var.ca_contract.partition}:rolesanywhere:${var.ca_contract.region}:${var.ca_contract.account_id}:crl/*",
    ]
  }

  # ListCrls returns every CRL in the account and Region, so it supports no
  # resource-level permission: scoping it to a trust-anchor or crl ARN denies the
  # call. Scoping is done on the response instead, by trustAnchorArn.
  statement {
    sid       = "ListCrlsForRetirement"
    actions   = ["rolesanywhere:ListCrls"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadRevocations"
    actions   = ["s3:GetObject"]
    resources = ["${var.ca_contract.artifacts_bucket_arn}/${var.revocations_s3_key}", "${var.ca_contract.artifacts_bucket_arn}/revocations/*"]
  }

  statement {
    sid       = "WriteCrlArtifacts"
    actions   = ["s3:PutObject"]
    resources = ["${var.ca_contract.artifacts_bucket_arn}/crl/*"]
  }

  # The core module's key policy matches this role by `aws:PrincipalArn` under the
  # account-root principal, so the signer also needs this identity grant. Split in
  # two on purpose: kms:MessageType/kms:SigningAlgorithm do not exist on a
  # GetPublicKey request, so a shared statement would deny the read.
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

resource "aws_iam_role_policy" "crl_issuer" {
  name   = "crl-issuer"
  role   = aws_iam_role.crl_issuer.id
  policy = data.aws_iam_policy_document.crl_issuer.json
}

resource "aws_lambda_function" "crl_issuer" {
  function_name = local.crl_lambda_name
  description   = "Activates the ${local.name} trust anchor from CAChainPublished and keeps its CRL fresh"
  role          = aws_iam_role.crl_issuer.arn

  filename         = data.archive_file.crl_issuer.output_path
  source_code_hash = data.archive_file.crl_issuer.output_base64sha256
  handler          = "lambda_function.handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 120
  memory_size      = 256

  # One CRL owner, one activation: concurrent runs would race ImportCrl and the
  # trust anchor update against each other.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      TRUST_ANCHOR_ARN   = aws_rolesanywhere_trust_anchor.this.arn
      TRUST_ANCHOR_ID    = aws_rolesanywhere_trust_anchor.this.id
      CA_BUNDLE_PARAM    = var.ca_contract.ca_bundle_ssm_param
      CA_EVENT_SOURCE    = var.ca_contract.event_source
      ISSUER_CERT_PARAM  = var.ca_contract.intermediate_ca_ssm_param
      KMS_KEY_ARN        = var.ca_contract.intermediate_kms_key_arn
      REVOCATIONS_S3_URI = "s3://${var.ca_contract.artifacts_bucket}/${var.revocations_s3_key}"
      CRL_OUTPUT_PREFIX  = "s3://${var.ca_contract.artifacts_bucket}/crl"
      CRL_VALIDITY_DAYS  = tostring(var.crl_validity_days)
      CRL_NAME_PREFIX    = "${local.name}-crl"
      LOG_LEVEL          = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.crl_issuer,
    aws_iam_role_policy.crl_issuer,
  ]

  tags = local.tags
}

###############################################################################
# Trigger 1: the CA published its chain (fan-out from the ceremony)
###############################################################################

resource "aws_cloudwatch_event_rule" "ca_chain_published" {
  name           = "${local.name}-ca-chain-published"
  description    = "Activate the ${local.name} trust anchor when the CA publishes its chain"
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

# No input transformer: the target receives the whole envelope, which is how the
# handler tells activation (event.source == cloudhsmca.pki) from a scheduled tick.
resource "aws_cloudwatch_event_target" "ca_chain_published" {
  rule           = aws_cloudwatch_event_rule.ca_chain_published.name
  event_bus_name = var.ca_contract.event_bus_name
  target_id      = "crl-issuer-activation"
  arn            = aws_lambda_function.crl_issuer.arn
}

resource "aws_lambda_permission" "ca_chain_published" {
  statement_id  = "AllowEventBridgeCaChainPublished"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crl_issuer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ca_chain_published.arn
}

###############################################################################
# Trigger 2: routine refresh
#
# A CRL whose nextUpdate has passed rejects every certificate, so this is not
# optional; the activation path only happens once per ceremony.
###############################################################################

resource "aws_cloudwatch_event_rule" "crl_refresh" {
  name                = "${local.name}-crl-refresh"
  description         = "Refresh the ${local.name} Roles Anywhere CRL"
  schedule_expression = var.crl_refresh_schedule
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "crl_refresh" {
  rule      = aws_cloudwatch_event_rule.crl_refresh.name
  target_id = "crl-issuer-refresh"
  arn       = aws_lambda_function.crl_issuer.arn

  input = jsonencode({ reason = "scheduled-refresh" })
}

resource "aws_lambda_permission" "crl_refresh" {
  statement_id  = "AllowEventBridgeCrlRefresh"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crl_issuer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crl_refresh.arn
}
