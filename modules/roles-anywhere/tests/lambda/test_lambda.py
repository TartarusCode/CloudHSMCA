#!/usr/bin/env python3
"""
Exercises the CRL Lambda that ships inside crl_issuer_lambda.tf.

The handler is not imported from a copy: it is extracted from the Terraform
heredoc exactly as Terraform renders it (strip the closing marker's indent),
so the test proves the bytes that get zipped, not a file that could drift from
them. boto3 is a stand-in backed by a real P-384 key, and the CRL that comes out
is verified with `openssl crl -verify` against its issuer.

Proves: TBSCertList encoding, the v2/SEQUENCE-OF shape, AKI lifted from the CA
certificate, digest signing, PEM encoding for ImportCrl (the API rejects raw
DER: "a CRL must be in PEM format"), the GetCrl round-trip comparison, and the
refusal to run when awscc owns the CRL object.

usage: python3 tests/lambda/test_lambda.py [module-dir]
"""
import base64
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import types

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(os.path.join(HERE, "..", ".."))
TF_PATH = os.path.join(MODULE, "crl_issuer_lambda.tf")

WORK = tempfile.mkdtemp(prefix="crl-lambda-test-")
ISSUER_KEY = ec.generate_private_key(ec.SECP384R1())


# --------------------------------------------------------------------------- #
# the shipped handler, extracted from the Terraform heredoc
# --------------------------------------------------------------------------- #

def load_handler():
    text = open(TF_PATH).read()
    start_marker = "    content  = <<-PY\n"
    end_marker = "\n      PY\n"
    if start_marker not in text:
        sys.exit("could not find the handler heredoc in %s" % TF_PATH)
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    body = text[start:end]
    # Terraform's <<- strips the indentation of the closing marker (6 spaces).
    lines = [l[6:] if l.startswith("      ") else l for l in body.split("\n")]
    source = "\n".join(lines)
    assert "def handler(" in source, source[:200]
    module = types.ModuleType("lambda_function")
    module.__file__ = "<crl_issuer_lambda.tf>"
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, source


class FakeBoto3(types.ModuleType):
    def __init__(self, issuer_pem, sink):
        super().__init__("boto3")
        self.__version__ = "harness-stub"
        self._issuer_pem = issuer_pem
        self._sink = sink

    def client(self, name, **kwargs):
        return {
            "ssm": _Ssm(self._issuer_pem),
            "kms": _Kms(),
            "s3": _S3(),
            "rolesanywhere": _RolesAnywhere(self._sink),
        }[name]


class _Ssm:
    def __init__(self, pem):
        self._pem = pem

    def get_parameter(self, Name):
        return {"Parameter": {"Value": self._pem}}


class _Kms:
    def get_public_key(self, KeyId):
        return {"SigningAlgorithms": ["ECDSA_SHA_384", "ECDSA_SHA_256"],
                "KeySpec": "ECC_NIST_P384"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "DIGEST", MessageType
        assert SigningAlgorithm == "ECDSA_SHA_384", SigningAlgorithm
        assert len(Message) == 48, "a P-384 digest must be 48 bytes"
        return {"Signature": ISSUER_KEY.sign(
            Message, ec.ECDSA(utils.Prehashed(hashes.SHA384())))}


class _NoSuchKey(Exception):
    pass


class _S3:
    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self):
        self.puts = []

    def get_object(self, Bucket, Key):
        payload = {"revoked": [
            {"serial": "0x0a1b2c", "revoked_at": "2026-11-02T00:00:00Z",
             "reason": "key_compromise"},
            {"serial": 4096},
        ]}
        return {"Body": io.BytesIO(json.dumps(payload).encode())}

    def put_object(self, **kwargs):
        self.puts.append(kwargs["Key"])


class _RolesAnywhere:
    def __init__(self, sink):
        self._sink = sink

    def import_crl(self, name, crlData, trustAnchorArn, enabled):
        self._sink["name"] = name
        self._sink["crlData"] = crlData
        return {"crl": {"crlId": "crl-123",
                        "crlArn": "arn:aws:rolesanywhere:us-west-2:1111:crl/123",
                        "name": name, "enabled": enabled}}

    def get_crl(self, crlId):
        assert crlId == "crl-123"
        # botocore hands a blob field back as bytes, exactly as imported.
        return {"crl": {"crlId": crlId, "enabled": True,
                        "crlData": self._sink["crlData"]}}


def make_issuer(work):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Corp Issuing CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ISSUER_KEY.public_key())
        .serial_number(1001)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc)
                         + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False,
            decipher_only=False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            ISSUER_KEY.public_key()), False)
        .sign(ISSUER_KEY, hashes.SHA384())
    )
    pem_path = os.path.join(work, "intermediate_ca.pem")
    with open(pem_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return pem_path, cert


def main():
    sink = {}
    pem_path, cert = make_issuer(WORK)

    sys.modules["boto3"] = FakeBoto3(open(pem_path).read(), sink)
    os.environ.update({
        "TRUST_ANCHOR_ARN": "arn:aws:rolesanywhere:us-west-2:111122223333:trust-anchor/abc",
        "ISSUER_CERT_PARAM": "/corp-pki/pki/intermediate_ca.pem",
        "KMS_KEY_ARN": "arn:aws:kms:us-west-2:111122223333:key/xyz",
        "REVOCATIONS_S3_URI": "s3://bucket/revocations/revoked.json",
        "CRL_OUTPUT_PREFIX": "s3://bucket/crl",
        "CRL_VALIDITY_DAYS": "7",
    })
    os.environ.pop("CRL_OWNER", None)

    handler_module, source = load_handler()
    print("handler extracted from crl_issuer_lambda.tf (%d bytes)" % len(source))

    result = handler_module.handler({"reason": "test"}, None)
    print(json.dumps(result, indent=2))

    # 1. the imported blob must be PEM, because ImportCrl documents PEM
    sent = sink["crlData"]
    assert isinstance(sent, bytes), type(sent)
    assert sent.lstrip().startswith(b"-----BEGIN X509 CRL"), sent[:40]
    pem_out = os.path.join(WORK, "crl.pem")
    open(pem_out, "wb").write(sent)
    der_out = os.path.join(WORK, "crl.der")
    open(der_out, "wb").write(x509.load_pem_x509_crl(sent)
                              .public_bytes(serialization.Encoding.DER))

    # 2. openssl must agree that the CRL is signed by this issuer
    verify = subprocess.run(
        ["openssl", "crl", "-in", der_out, "-inform", "DER",
         "-CAfile", pem_path, "-noout"], capture_output=True, text=True)
    if verify.returncode != 0:
        sys.exit("openssl rejected the CRL:\n%s\n%s" % (verify.stdout, verify.stderr))
    print("openssl crl -verify:", verify.stderr.strip() or "OK")

    # 3. the v2 CRL must carry both entries, crlNumber and the CA's key id
    parsed = x509.load_pem_x509_crl(sent)
    serials = sorted(r.serial_number for r in parsed)
    assert serials == [4096, 0x0A1B2C], [hex(s) for s in serials]
    assert parsed.get_revoked_certificate_by_serial_number(0x0A1B2C) is not None
    issuer_ski = cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value.digest
    aki = parsed.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value.key_identifier
    assert aki is not None, "CRL carries no authorityKeyIdentifier key id"
    assert aki == issuer_ski, (aki.hex(), issuer_ski.hex())
    print("crlNumber:", parsed.extensions.get_extension_for_class(
        x509.CRLNumber).value.crl_number)
    print("revoked serials:", [hex(s) for s in serials])
    print("AKI matches the issuer SKI")

    # 4. the awscc path must be refused, so the two owners cannot fork
    os.environ["CRL_OWNER"] = "awscc"
    try:
        handler_module.handler({}, None)
    except RuntimeError as exc:
        assert "awscc" in str(exc), exc
        print("refuses to import when CRL_OWNER=awscc:", str(exc)[:60], "...")
    else:
        sys.exit("FAIL: handler imported a CRL while awscc owns the object")

    # 5. the empty-revocation-set variant must still be a valid CRL
    os.environ.pop("REVOCATIONS_S3_URI")
    os.environ.pop("CRL_OWNER")
    sink.clear()
    handler_module.handler({}, None)
    empty = x509.load_pem_x509_crl(sink["crlData"])
    assert list(empty) == [], list(empty)
    print("empty-revocation CRL is valid, 0 entries")

    print("\nLAMBDA HARNESS: PASS (work dir %s)" % WORK)


if __name__ == "__main__":
    main()
