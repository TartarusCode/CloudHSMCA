"""Minimal boto3 stand-in: only kms, backed by a local P-256 key."""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

KEY_PATH = os.environ["FAKE_KMS_KEY"]
CALLS = os.environ.get("FAKE_KMS_LOG", "/dev/null")
__version__ = "1.34.0-harness-stub"


def _key():
    return serialization.load_pem_private_key(open(KEY_PATH, "rb").read(), None)


class _Kms:
    def get_public_key(self, KeyId=None):
        with open(CALLS, "a") as fh:
            fh.write("get_public_key %s\n" % KeyId)
        return {
            "KeyId": KeyId,
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": _key().public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo),
        }

    def sign(self, KeyId=None, Message=None, MessageType=None, SigningAlgorithm=None):
        assert MessageType == "DIGEST", "harness only supports DIGEST signing"
        assert SigningAlgorithm == "ECDSA_SHA_256", SigningAlgorithm
        with open(CALLS, "a") as fh:
            fh.write("sign %s digest=%d\n" % (KeyId, len(Message)))
        return {"Signature": _key().sign(
            Message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))}


def client(name, **kwargs):
    if name == "kms":
        return _Kms()
    raise RuntimeError("harness boto3 only implements kms, asked for %r" % name)
