#!/usr/bin/env python3
"""
Unit harness for the ALB mTLS sync Lambda in modules/alb-mtls/sync_lambda.tf.

It extracts the handler from the Terraform heredoc (the bytes that get zipped,
not a copy) and runs it against stubs for SSM, S3, KMS and ELBv2 backed by a real
P-384 key, so the CRL it signs is verifiable with openssl.

Proves:
  * CAChainPublished uploads the chain, points ModifyTrustStore at that exact
    object version, then imports a CRL;
  * a scheduled tick before publication returns {"skipped": ...} and touches
    neither S3 nor ELBv2;
  * a scheduled tick after publication adds the new CRL *before* removing the
    previous RevocationId (no window with no CRL);
  * an activation event with no chain raises instead of installing nothing;
  * the CRL is PEM, openssl-verifiable against the issuer, carries the issuer's
    key id, and contains the revoked serials.

usage: python3 modules/alb-mtls/tests/lambda/test_lambda.py [module-dir]
"""
import datetime
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import types

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(
    os.path.join(HERE, "..", ".."))
TF_PATH = os.path.join(MODULE, "sync_lambda.tf")

WORK = tempfile.mkdtemp(prefix="alb-mtls-test-")
ISSUER_KEY = ec.generate_private_key(ec.SECP384R1())


# --------------------------------------------------------------------------- #
# the shipped handler, extracted from the Terraform heredoc
# --------------------------------------------------------------------------- #

def load_handler():
    text = open(TF_PATH).read()
    start = text.index("<<-PY") + len("<<-PY")
    end = text.index("\n    PY", start)
    body = text[start:end]
    lines = []
    for line in body.splitlines():
        lines.append(line[6:] if line.startswith("      ") else line)
    source = "\n".join(lines).strip("\n") + "\n"
    module = types.ModuleType("lambda_function")
    module.__file__ = "<sync_lambda.tf>"
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, source


def _check_kwargs(service, operation, kwargs):
    """Validate a stub call against the real botocore model when it is installed.

    A hand-written stub only proves the handler agrees with itself: this harness
    happily accepted `add_trust_store_revocations(Revocations=[...])`, which the
    live API rejects with ParamValidationError because the parameter is
    RevocationContents and each element is an S3Bucket/S3Key/S3ObjectVersion
    triple. Checking the model turns the stub into a statement about the API.
    """
    try:
        import botocore.session
    except ImportError:
        return
    model = botocore.session.get_session().get_service_model(service)
    shape = model.operation_model(operation).input_shape
    allowed = set((shape.members or {}) if shape else {})
    unknown = sorted(set(kwargs) - allowed)
    assert not unknown, "%s:%s does not accept %s (accepts %s)" % (
        service, operation, unknown, sorted(allowed))
    for key, value in kwargs.items():
        member = (shape.members or {}).get(key)
        # list-of-structure parameters: check the element keys too
        inner = getattr(getattr(member, "member", None), "members", None)
        if inner and isinstance(value, (list, tuple)) and value and isinstance(value[0], dict):
            bad = sorted(set(value[0]) - set(inner))
            assert not bad, "%s:%s.%s element does not accept %s (accepts %s)" % (
                service, operation, key, bad, sorted(inner))


class _ParameterNotFound(Exception):
    pass


class _Ssm:
    class exceptions:
        ParameterNotFound = _ParameterNotFound

    def __init__(self, state):
        self._state = state

    def get_parameter(self, Name, WithDecryption=True):
        _check_kwargs("ssm", "GetParameter",
                      {"Name": Name, "WithDecryption": WithDecryption})
        value = self._state["params"].get(Name)
        if value is None:
            raise _ParameterNotFound(Name)
        return {"Parameter": {"Value": value}}


class _Kms:
    def get_public_key(self, KeyId):
        _check_kwargs("kms", "GetPublicKey", {"KeyId": KeyId})
        return {"SigningAlgorithms": ["ECDSA_SHA_384", "ECDSA_SHA_256"],
                "KeySpec": "ECC_NIST_P384"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        _check_kwargs("kms", "Sign", {"KeyId": KeyId, "Message": Message,
                                     "MessageType": MessageType,
                                     "SigningAlgorithm": SigningAlgorithm})
        assert MessageType == "DIGEST", MessageType
        assert SigningAlgorithm == "ECDSA_SHA_384", SigningAlgorithm
        assert len(Message) == 48, "a P-384 digest must be 48 bytes"
        return {"Signature": ISSUER_KEY.sign(
            Message, ec.ECDSA(utils.Prehashed(hashes.SHA384())))}


class _S3:
    def __init__(self, state):
        self._state = state

    def put_object(self, Bucket, Key, Body, ContentType, ServerSideEncryption):
        _check_kwargs("s3", "PutObject", {
            "Bucket": Bucket, "Key": Key, "Body": Body,
            "ContentType": ContentType, "ServerSideEncryption": ServerSideEncryption})
        assert ServerSideEncryption == "AES256", ServerSideEncryption
        self._state["calls"].append(("s3.put", Key))
        self._state["puts"] = self._state.get("puts", 0) + 1
        version = "v%d" % self._state["puts"]
        self._state["objects"][Key] = Body
        return {"VersionId": version}


class _Elbv2:
    def __init__(self, state):
        self._state = state

    def modify_trust_store(self, TrustStoreArn, CaCertificatesBundleS3Bucket,
                           CaCertificatesBundleS3Key,
                           CaCertificatesBundleS3ObjectVersion):
        _check_kwargs("elbv2", "ModifyTrustStore", {
            "TrustStoreArn": TrustStoreArn,
            "CaCertificatesBundleS3Bucket": CaCertificatesBundleS3Bucket,
            "CaCertificatesBundleS3Key": CaCertificatesBundleS3Key,
            "CaCertificatesBundleS3ObjectVersion": CaCertificatesBundleS3ObjectVersion})
        self._state["calls"].append(("elbv2.modify", CaCertificatesBundleS3ObjectVersion))
        self._state["bundle_version"] = CaCertificatesBundleS3ObjectVersion
        return {"TrustStores": [{"TrustStoreArn": TrustStoreArn}]}

    def describe_trust_store_revocations(self, TrustStoreArn):
        _check_kwargs("elbv2", "DescribeTrustStoreRevocations",
                      {"TrustStoreArn": TrustStoreArn})
        return {"TrustStoreRevocations": list(self._state["revocations"])}

    def add_trust_store_revocations(self, TrustStoreArn, RevocationContents):
        _check_kwargs("elbv2", "AddTrustStoreRevocations",
                      {"TrustStoreArn": TrustStoreArn,
                       "RevocationContents": RevocationContents})
        self._state["calls"].append(
            ("elbv2.add", RevocationContents[0]["S3ObjectVersion"]))
        new = {"RevocationId": "rev-new-%d" % (len(self._state["calls"])),
               "RevocationType": "CRL",
               "RevocationS3ObjectVersion": RevocationContents[0]["S3ObjectVersion"]}
        self._state["revocations"].append(new)
        return {"TrustStoreRevocations": [new]}

    def remove_trust_store_revocations(self, TrustStoreArn, RevocationIds):
        _check_kwargs("elbv2", "RemoveTrustStoreRevocations",
                      {"TrustStoreArn": TrustStoreArn, "RevocationIds": RevocationIds})
        self._state["calls"].append(("elbv2.remove", list(RevocationIds)))
        self._state["revocations"] = [
            r for r in self._state["revocations"] if r["RevocationId"] not in RevocationIds]
        return {"TrustStoreRevocations": []}


class FakeBoto3(types.ModuleType):
    def __init__(self, state):
        super().__init__("boto3")
        self.__version__ = "harness-stub"
        self._state = state

    def client(self, name, **kwargs):
        return {
            "ssm": _Ssm(self._state),
            "kms": _Kms(),
            "s3": _S3(self._state),
            "elbv2": _Elbv2(self._state),
        }[name]


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
    state = {"params": {}, "objects": {}, "revocations": [], "calls": []}
    pem_path, cert = make_issuer(WORK)
    issuer_pem = open(pem_path).read()
    bundle_pem = issuer_pem + issuer_pem

    state["params"].update({
        "/corp-pki/pki/ca_bundle.pem": bundle_pem,
        "/corp-pki/pki/intermediate_ca.pem": issuer_pem,
        "/corp-pki/pki/revoked-serials": json.dumps({"revoked": [
            {"serial": "0x0a1b2c", "revoked_at": "2026-11-02T00:00:00Z",
             "reason": "key_compromise"},
            {"serial": 4096},
        ]}),
    })

    sys.modules["boto3"] = FakeBoto3(state)
    os.environ.update({
        "TRUST_STORE_ARN": "arn:aws:elasticloadbalancing:us-west-2:111122223333:truststore/app/x/abc",
        "ARTIFACTS_BUCKET": "corp-pki-pki-artifacts",
        "BUNDLE_KEY": "alb-mtls/corp-pki/ca_bundle.pem",
        "CRL_KEY": "alb-mtls/corp-pki/crl.pem",
        "CA_BUNDLE_PARAM": "/corp-pki/pki/ca_bundle.pem",
        "ISSUER_CERT_PARAM": "/corp-pki/pki/intermediate_ca.pem",
        "REVOKED_SERIALS_PARAM": "/corp-pki/pki/revoked-serials",
        "KMS_KEY_ARN": "arn:aws:kms:us-west-2:111122223333:key/xyz",
        "CA_EVENT_SOURCE": "cloudhsmca.pki",
        "CRL_VALIDITY_DAYS": "7",
    })

    handler_module, source = load_handler()
    print("handler extracted from sync_lambda.tf (%d bytes)" % len(source))

    activation_event = {
        "version": "0",
        "source": "cloudhsmca.pki",
        "detail-type": "CAChainPublished",
        "detail": {"ca_name": "corp-pki"},
    }

    # --- path A: activation ------------------------------------------------
    print("\n[1] CAChainPublished: upload the chain, switch the trust store, import a CRL")
    result = handler_module.handler(activation_event, None)
    print(json.dumps(result, indent=2))

    assert result.get("activated") is True, result
    assert state["bundle_version"] == result["bundleVersionId"], state
    assert ("s3.put", "alb-mtls/corp-pki/ca_bundle.pem") in state["calls"], state["calls"]
    assert ("elbv2.modify", result["bundleVersionId"]) in state["calls"], state["calls"]
    assert result["revocationIds"], result
    assert not any(c[0] == "elbv2.remove" for c in state["calls"]), "removed a CRL on first import"
    print("bundle version:", result["bundleVersionId"], "| crl version:", result["crlVersionId"])

    # --- the CRL itself, as uploaded ---------------------------------------
    crl_pem = state["objects"]["alb-mtls/corp-pki/crl.pem"]
    assert crl_pem.lstrip().startswith(b"-----BEGIN X509 CRL"), crl_pem[:40]
    crl_path = os.path.join(WORK, "crl.pem")
    open(crl_path, "wb").write(crl_pem)
    parsed = x509.load_pem_x509_crl(crl_pem)
    der_path = os.path.join(WORK, "crl.der")
    open(der_path, "wb").write(parsed.public_bytes(serialization.Encoding.DER))
    verify = subprocess.run(
        ["openssl", "crl", "-in", der_path, "-inform", "DER",
         "-CAfile", pem_path, "-noout"], capture_output=True, text=True)
    if verify.returncode != 0:
        sys.exit("openssl rejected the CRL:\n%s\n%s" % (verify.stdout, verify.stderr))
    print("openssl crl -verify:", verify.stderr.strip() or "OK")

    serials = sorted(r.serial_number for r in parsed)
    assert serials == [4096, 0x0A1B2C], [hex(s) for s in serials]
    aki = parsed.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value.key_identifier
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert aki == ski, (aki.hex(), ski.hex())
    print("revoked serials:", [hex(s) for s in serials], "| AKI matches the issuer SKI")

    # --- path B: scheduled tick before the ceremony -------------------------
    print("\n[2] scheduled tick with no published chain: skip, touch nothing")
    state["params"]["/corp-pki/pki/ca_bundle.pem"] = "PENDING-CEREMONY"
    state["calls"].clear()
    skipped = handler_module.handler({"reason": "scheduled-refresh"}, None)
    print(json.dumps(skipped, indent=2))
    assert skipped == {"ok": True, "skipped": "chain-not-published",
                       "reason": "scheduled-refresh"}, skipped
    assert state["calls"] == [], state["calls"]

    # --- path C: scheduled tick after the ceremony --------------------------
    print("\n[3] scheduled tick after publication: add the new CRL, then remove the old one")
    state["params"]["/corp-pki/pki/ca_bundle.pem"] = bundle_pem
    state["calls"].clear()
    state["revocations"] = [{"RevocationId": "rev-old", "RevocationType": "CRL"}]
    refreshed = handler_module.handler({"reason": "scheduled-refresh"}, None)
    assert refreshed.get("activated") is False, refreshed
    assert refreshed["replacedRevocations"] == ["rev-old"], refreshed
    order = [c[0] for c in state["calls"]]
    assert order.index("elbv2.add") < order.index("elbv2.remove"), order
    assert ("elbv2.remove", ["rev-old"]) in state["calls"], state["calls"]
    assert not any(c[0] == "elbv2.modify" for c in state["calls"]), "a refresh must not touch the bundle"
    print("call order:", order)

    # --- path D: activation without a chain ---------------------------------
    print("\n[4] CAChainPublished with no chain: fail loudly")
    state["params"]["/corp-pki/pki/ca_bundle.pem"] = "PENDING-CEREMONY"
    try:
        handler_module.handler(activation_event, None)
    except RuntimeError as exc:
        assert "no usable chain" in str(exc), exc
        print("refused to activate without a chain:", str(exc)[:70], "...")
    else:
        sys.exit("FAIL: activation ran with no chain to install")

    print("\nALB-MTLS LAMBDA HARNESS: PASS (work dir %s)" % WORK)


if __name__ == "__main__":
    main()
