#!/usr/bin/env python3
"""
kms_ca_tool.py — issue X.509 artifacts for an AWS IAM Roles Anywhere PKI whose
private keys never exist in a file: the Intermediate CA key lives in AWS KMS
(asymmetric SIGN_VERIFY) and the offline Root CA key lives in AWS CloudHSM.

Why this file exists
--------------------
`cryptography.x509` can only sign with a local private-key object, so every
builder below is used in three steps:

  1. build the object with a THROWAWAY local key -> gives us the exact
     DER-encoded to-be-signed bytes (tbsCertificate / TBSCertList /
     CertificationRequestInfo) that the real signer must sign;
  2. hand those bytes to a Signer, which returns a raw signature
     (KMS `sign(MessageType='DIGEST')`, or `cloudhsm-cli crypto sign ecdsa`);
  3. splice tbs + signatureAlgorithm + signatureValue back into one SEQUENCE.

Step 3 is done with the small DER reader/writer at the top of this file, never
by re-encoding a parsed object: a re-encoded TBS is not guaranteed
byte-identical, and a single differing byte invalidates the signature. Every
artifact produced here is therefore re-parsed and its signature VERIFIED
against the issuer's public key before it is written to disk.

Signers
-------
  kms    in-region AWS KMS asymmetric key (production Intermediate CA)
  hsm    AWS CloudHSM Client SDK 5 via `cloudhsm-cli crypto sign ecdsa`
  local  a private key file; TESTING/offline-verification only

Subcommands
-----------
  spki-from-point         rebuild a SubjectPublicKeyInfo DER from the HSM's
                          reported EC point (secp384r1 etc.)
  self-sign-root          self-signed Root CA certificate
  create-intermediate-csr CSR for the KMS Intermediate CA key
  sign-csr                issue a certificate for a CSR (Root signs Intermediate)
  sign-leaf-csr           issue a clientAuth leaf for a workload
  generate-crl            build a DER CRL and (optionally) import it into
                          IAM Roles Anywhere

Extension sets come from the OpenSSL configuration rendered by Terraform
(scripts/root_ca.cnf.tftpl, scripts/intermediate_ca.cnf.tftpl) so there is one
definition of the X.509 profiles, consumed by both `openssl` and this tool.

Requires: python3 >= 3.9, `cryptography` (>= 42), `boto3` (only for --signer kms
and --upload).
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError as exc:  # pragma: no cover - dependency guard
    sys.exit(
        "kms_ca_tool: the 'cryptography' package is required "
        "(python3 -m pip install 'cryptography>=42'): %s" % exc
    )


# --------------------------------------------------------------------------- #
# DER primitives
# --------------------------------------------------------------------------- #

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_SEQUENCE = 0x30
TAG_OID = 0x06


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + der_len(len(payload)) + payload


def der_oid(dotted: str) -> bytes:
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


def der_read(buf: bytes, off: int = 0):
    """Return (tag, header_len, content_len, total_len) for the TLV at `off`."""
    if off + 2 > len(buf):
        raise ValueError("DER: truncated element at offset %d" % off)
    tag = buf[off]
    first = buf[off + 1]
    if first < 0x80:
        return tag, 2, first, 2 + first
    count = first & 0x7F
    if count == 0 or count > 4 or off + 2 + count > len(buf):
        raise ValueError("DER: unsupported length at offset %d" % off)
    length = int.from_bytes(buf[off + 2 : off + 2 + count], "big")
    header = 2 + count
    return tag, header, length, header + length


def der_children(der: bytes):
    """Yield (tag, raw_tlv) for each direct child of a constructed TLV."""
    tag, hlen, clen, total = der_read(der, 0)
    if total != len(der):
        raise ValueError("DER: trailing bytes after element")
    off = hlen
    end = hlen + clen
    while off < end:
        ctag, chlen, cclen, ctotal = der_read(der, off)
        yield ctag, der[off : off + ctotal]
        off += ctotal


def der_bit_string(payload: bytes) -> bytes:
    """BIT STRING with zero unused bits (signatures, public keys)."""
    return der_tlv(TAG_BIT_STRING, b"\x00" + payload)


def der_integer(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:  # keep it positive
        body = b"\x00" + body
    return der_tlv(TAG_INTEGER, body)


def ecdsa_rs_to_der(raw: bytes) -> bytes:
    """CloudHSM returns r||s; X.509 wants SEQUENCE { INTEGER r, INTEGER s }."""
    if len(raw) % 2:
        raise ValueError("ECDSA r||s signature has odd length %d" % len(raw))
    half = len(raw) // 2
    return der_tlv(TAG_SEQUENCE, der_integer(int.from_bytes(raw[:half], "big"))
                   + der_integer(int.from_bytes(raw[half:], "big")))


def ecdsa_der_to_rs(der: bytes) -> bytes:
    ints = [int.from_bytes(child[der_read(child, 0)[1]:], "big")
            for tag, child in der_children(der) if tag == TAG_INTEGER]
    if len(ints) != 2:
        raise ValueError("ECDSA signature is not SEQUENCE{INTEGER,INTEGER}")
    width = max(32, max(i.bit_length() for i in ints) // 8 + 1)
    return b"".join(i.to_bytes(width, "big") for i in ints)


# --------------------------------------------------------------------------- #
# Signature algorithms
# --------------------------------------------------------------------------- #

class SigAlg:
    def __init__(self, name, oid, hash_alg, kms_name, openssl_name):
        self.name = name
        self.oid = oid
        self.hash_alg = hash_alg
        self.kms_name = kms_name
        self.openssl_name = openssl_name

    def digest(self, message: bytes) -> bytes:
        h = hashlib.new(self.openssl_name)
        h.update(message)
        return h.digest()


SIG_ALGS = {
    "ECDSA_SHA_256": SigAlg("ECDSA_SHA_256", "1.2.840.10045.4.3.2", hashes.SHA256(),
                            "ECDSA_SHA_256", "sha256"),
    "ECDSA_SHA_384": SigAlg("ECDSA_SHA_384", "1.2.840.10045.4.3.3", hashes.SHA384(),
                            "ECDSA_SHA_384", "sha384"),
    "ECDSA_SHA_512": SigAlg("ECDSA_SHA_512", "1.2.840.10045.4.3.4", hashes.SHA512(),
                            "ECDSA_SHA_512", "sha512"),
    "RSASSA_PKCS1_V1_5_SHA_256": SigAlg("RSASSA_PKCS1_V1_5_SHA_256",
                                        "1.2.840.113549.1.1.11", hashes.SHA256(),
                                        "RSASSA_PKCS1_V1_5_SHA_256", "sha256"),
}

CURVE_BY_ALG = {
    "ECDSA_SHA_256": "secp256r1",
    "ECDSA_SHA_384": "secp384r1",
    "ECDSA_SHA_512": "secp521r1",
}


def sig_alg_for_key_spec(key_spec: str) -> SigAlg:
    return {
        "ECC_NIST_P256": SIG_ALGS["ECDSA_SHA_256"],
        "ECC_NIST_P384": SIG_ALGS["ECDSA_SHA_384"],
        "ECC_NIST_P521": SIG_ALGS["ECDSA_SHA_512"],
        "RSA_2048": SIG_ALGS["RSASSA_PKCS1_V1_5_SHA_256"],
        "RSA_3072": SIG_ALGS["RSASSA_PKCS1_V1_5_SHA_256"],
        "RSA_4096": SIG_ALGS["RSASSA_PKCS1_V1_5_SHA_256"],
    }[key_spec]


# --------------------------------------------------------------------------- #
# Signers
# --------------------------------------------------------------------------- #

class Signer:
    """A private key that can only sign, never be read."""

    alg: SigAlg
    public_key: object  # cryptography public key object (verification only)

    def public_key_der(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_digest(self, digest: bytes) -> bytes:  # -> DER (EC) / raw (RSA)
        raise NotImplementedError

    def describe(self) -> str:
        return "%s (%s)" % (self.__class__.__name__, self.alg.name)


class LocalSigner(Signer):
    """TESTING ONLY: a plain key file. Never used for a production CA."""

    def __init__(self, path: str):
        with open(path, "rb") as fh:
            self._key = serialization.load_pem_private_key(fh.read(), password=None)
        self.public_key = self._key.public_key()
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            self.alg = {256: SIG_ALGS["ECDSA_SHA_256"], 384: SIG_ALGS["ECDSA_SHA_384"],
                        521: SIG_ALGS["ECDSA_SHA_512"]}[self._key.key_size]
        elif isinstance(self._key, rsa.RSAPrivateKey):
            self.alg = SIG_ALGS["RSASSA_PKCS1_V1_5_SHA_256"]
        else:
            raise SystemExit("local signer: unsupported key type")

    def sign_digest(self, digest: bytes) -> bytes:
        prehashed = utils.Prehashed(self.alg.hash_alg)
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            return self._key.sign(digest, ec.ECDSA(prehashed))
        return self._key.sign(digest, padding.PKCS1v15(), prehashed)


class KmsSigner(Signer):
    """AWS KMS asymmetric key. The key material never leaves the HSM fleet."""

    def __init__(self, key_id: str, region: str | None = None):
        import boto3  # imported lazily so `--signer local` needs no boto3

        self._kms = boto3.client("kms", region_name=region)
        self.key_id = key_id
        meta = self._kms.get_public_key(KeyId=key_id)
        self.public_key = serialization.load_der_public_key(meta["PublicKey"])
        allowed = meta.get("SigningAlgorithms") or []
        chosen = None
        for candidate in ("ECDSA_SHA_384", "ECDSA_SHA_256", "ECDSA_SHA_512",
                          "RSASSA_PKCS1_V1_5_SHA_256"):
            if candidate in allowed:
                chosen = candidate
                break
        if chosen is None:
            chosen = sig_alg_for_key_spec(
                meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
            ).name
        self.alg = SIG_ALGS[chosen]

    def sign_digest(self, digest: bytes) -> bytes:
        resp = self._kms.sign(
            KeyId=self.key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=self.alg.kms_name,
        )
        return resp["Signature"]


class HsmSigner(Signer):
    """
    AWS CloudHSM Client SDK 5 signer.

    `cloudhsm-cli crypto sign ecdsa` returns the signature as base64 of the raw
    r||s concatenation (verified against the SDK 5 command reference), so it is
    converted to DER here. The public key is never exported from the HSM: it is
    rebuilt from the EC point that the HSM reported at key generation
    (`spki-from-point`), which is why --hsm-public-key is required.
    """

    def __init__(self, key_label: str, public_key_path: str, curve: str,
                 cli: str = "/opt/cloudhsm/bin/cloudhsm-cli",
                 pin: str | None = None, cluster_id: str | None = None):
        self.key_label = key_label
        self.cli = cli
        self.cluster_id = cluster_id
        self.pin = pin or os.environ.get("CLOUDHSM_PIN")
        if not self.pin or ":" not in self.pin:
            raise SystemExit(
                "hsm signer: set CLOUDHSM_PIN=<crypto-user>:<password>"
            )
        self._user, self._password = self.pin.split(":", 1)
        with open(public_key_path, "rb") as fh:
            blob = fh.read()
        try:
            self.public_key = serialization.load_der_public_key(blob)
        except ValueError:
            self.public_key = serialization.load_pem_public_key(blob)
        bits = self.public_key.key_size
        self.alg = {256: SIG_ALGS["ECDSA_SHA_256"],
                    384: SIG_ALGS["ECDSA_SHA_384"],
                    521: SIG_ALGS["ECDSA_SHA_512"]}[bits]
        expected = CURVE_BY_ALG[self.alg.name]
        if curve != expected:
            raise SystemExit(
                "hsm signer: --hsm-curve %s does not match public key curve %s"
                % (curve, expected)
            )

    def sign_digest(self, digest: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(prefix="hsm-digest-") as fh:
            fh.write(digest)
            fh.flush()
            cmd = "crypto sign ecdsa --key-filter label=%s --hash-function %s " \
                  "--data-path %s --data-type digest" % (
                      self.key_label, self.alg.openssl_name, fh.name)
            if self.cluster_id:
                cmd += " --cluster-id %s" % self.cluster_id
            script = "\n".join([
                "login --username %s --role crypto-user --password %s"
                % (self._user, self._password),
                cmd,
                "quit",
                "",
            ])
            proc = subprocess.run(
                [self.cli, "interactive"], input=script, capture_output=True,
                text=True, timeout=120,
            )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise SystemExit("cloudhsm-cli exited %d:\n%s" % (proc.returncode, out))
        match = re.search(r'"signature"\s*:\s*"([A-Za-z0-9+/=]+)"', out)
        if not match:
            raise SystemExit("cloudhsm-cli returned no signature:\n%s" % out)
        raw = base64.b64decode(match.group(1))
        return ecdsa_rs_to_der(raw)


# --------------------------------------------------------------------------- #
# Splicing + verification
# --------------------------------------------------------------------------- #

_PLACEHOLDER_CURVE = {
    "ECDSA_SHA_256": ec.SECP256R1,
    "ECDSA_SHA_384": ec.SECP384R1,
    "ECDSA_SHA_512": ec.SECP521R1,
}


def _placeholder_key(alg: SigAlg):
    if alg.name.startswith("ECDSA"):
        return ec.generate_private_key(_PLACEHOLDER_CURVE[alg.name]())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def assemble(tbs_raw: bytes, alg: SigAlg, signature: bytes) -> bytes:
    """SEQUENCE { TBS, AlgorithmIdentifier, BIT STRING signature }."""
    if alg.name.startswith("RSASSA"):  # RSA AlgorithmIdentifier requires NULL
        alg_der = der_tlv(TAG_SEQUENCE, der_oid(alg.oid) + der_tlv(0x05, b""))
    else:
        alg_der = der_tlv(TAG_SEQUENCE, der_oid(alg.oid))
    return der_tlv(TAG_SEQUENCE, tbs_raw + alg_der + der_bit_string(signature))


def splice(template_der: bytes, alg: SigAlg, signature: bytes) -> bytes:
    """
    template_der is SEQUENCE { TBS, AlgorithmIdentifier, BIT STRING } — the
    shape shared by Certificate, CertificateList and CertificationRequest.
    Returns the same SEQUENCE with the real algorithm and signature.
    """
    outer = list(der_children(template_der))
    if len(outer) != 3:
        raise ValueError("DER: expected 3 elements, got %d" % len(outer))
    tbs_raw = outer[0][1]
    if outer[1][0] != TAG_SEQUENCE:
        raise ValueError("DER: signatureAlgorithm is not a SEQUENCE")
    return assemble(tbs_raw, alg, signature)


def _tbs_of(der: bytes) -> bytes:
    return list(der_children(der))[0][1]


def verify_signature(public_key, signature: bytes, tbs: bytes, alg: SigAlg) -> None:
    if alg.name.startswith("ECDSA"):
        public_key.verify(signature, tbs, ec.ECDSA(alg.hash_alg))
    else:
        public_key.verify(signature, tbs, padding.PKCS1v15(), alg.hash_alg)


def _now(offset_days: int = 0) -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=offset_days)


# --------------------------------------------------------------------------- #
# OpenSSL configuration -> extension set
# --------------------------------------------------------------------------- #

def _parse_openssl_extensions(path: str, section: str):
    """
    Read one [section] of an OpenSSL configuration and return a list of
    (extension, critical). Only the keys this PKI emits are supported, so an
    unexpected line fails loudly instead of being silently ignored.
    """
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    current = None
    values = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != section:
            continue
        if "=" not in line:
            raise SystemExit("%s: [%s] line is not 'key = value': %r"
                             % (path, section, raw))
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    if not values:
        raise SystemExit("%s: section [%s] missing or empty" % (path, section))

    out = []
    for key, value in values.items():
        parts = [p.strip() for p in value.split(",")]
        critical = bool(parts) and parts[0].lower() == "critical"
        if critical:
            parts = parts[1:]
        args = [p for p in parts if p]

        if key == "basicConstraints":
            ca = False
            pathlen = None
            for arg in args:
                if arg.upper() == "CA:TRUE":
                    ca = True
                elif arg.upper() == "CA:FALSE":
                    ca = False
                elif arg.lower().startswith("pathlen:"):
                    pathlen = int(arg.split(":", 1)[1])
                else:
                    raise SystemExit("basicConstraints: unsupported %r" % arg)
            out.append((x509.BasicConstraints(ca=ca, path_length=pathlen), critical))
        elif key == "keyUsage":
            flags = {a.lower() for a in args}
            known = {
                "digitalsignature": "digital_signature",
                "nonrepudiation": "content_commitment",
                "contentcommitment": "content_commitment",
                "keyencipherment": "key_encipherment",
                "dataencipherment": "data_encipherment",
                "keyagreement": "key_agreement",
                "keycertsign": "key_cert_sign",
                "crlsign": "crl_sign",
                "encipheronly": "encipher_only",
                "decipheronly": "decipher_only",
            }
            kwargs = {field: False for field in known.values()}
            for flag in flags:
                if flag not in known:
                    raise SystemExit("keyUsage: unsupported %r" % flag)
                kwargs[known[flag]] = True
            out.append((x509.KeyUsage(**kwargs), critical))
        elif key == "subjectKeyIdentifier":
            if not args or args[0].lower() != "hash":
                raise SystemExit("subjectKeyIdentifier: only 'hash' is supported")
            out.append(("SKI", critical))
        elif key == "authorityKeyIdentifier":
            joined = ",".join(args).lower().replace(" ", "")
            if joined not in ("keyid:always,issuer", "keyid:always"):
                raise SystemExit(
                    "authorityKeyIdentifier: only 'keyid:always, issuer' is supported")
            out.append(("AKI", critical))
        elif key == "extendedKeyUsage":
            eku_map = {
                "clientauth": ExtendedKeyUsageOID.CLIENT_AUTH,
                "serverauth": ExtendedKeyUsageOID.SERVER_AUTH,
                "codesigning": ExtendedKeyUsageOID.CODE_SIGNING,
            }
            oids = []
            for arg in args:
                if arg.lower() not in eku_map:
                    raise SystemExit("extendedKeyUsage: unsupported %r" % arg)
                oids.append(eku_map[arg.lower()])
            out.append((x509.ExtendedKeyUsage(oids), critical))
        else:
            raise SystemExit("[%s] unsupported extension %r" % (section, key))
    return out


def _resolve_extensions(extensions, subject_public_key, issuer_ski):
    resolved = []
    for ext, critical in extensions:
        if ext == "SKI":
            ext = x509.SubjectKeyIdentifier.from_public_key(subject_public_key)
        elif ext == "AKI":
            if issuer_ski is None:
                raise SystemExit("AKI requested but no issuer SubjectKeyIdentifier")
            ext = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_ski)
        resolved.append((ext, critical))
    return resolved


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def _write_pem(der: bytes, kind: str, out_path: str, also_der: bool) -> None:
    if kind == "certificate":
        obj = x509.load_der_x509_certificate(der)
    elif kind == "crl":
        obj = x509.load_der_x509_crl(der)
    else:
        obj = x509.load_der_x509_csr(der)
    with open(out_path, "wb") as fh:
        fh.write(obj.public_bytes(serialization.Encoding.PEM))
    if also_der:
        der_path = os.path.splitext(out_path)[0] + ".der"
        with open(der_path, "wb") as fh:
            fh.write(der)
        print("wrote %s" % der_path)
    print("wrote %s" % out_path)


def _name_from_cnf(path: str, section: str) -> x509.Name:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    fields = {"CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME,
              "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
              "C": NameOID.COUNTRY_NAME, "L": NameOID.LOCALITY_NAME,
              "ST": NameOID.STATE_OR_PROVINCE_NAME}
    order = ["C", "ST", "L", "O", "OU", "CN"]
    values = {}
    current = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != section or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in fields:
            raise SystemExit("%s: [%s] unsupported DN attribute %r"
                             % (path, section, key))
        values[key] = value.strip()
    if "CN" not in values:
        raise SystemExit("%s: [%s] has no CN" % (path, section))
    return x509.Name([x509.NameAttribute(fields[k], values[k])
                      for k in order if k in values])


def cmd_spki_from_point(args) -> None:
    curves = {"secp256r1": (256, "1.2.840.10045.3.1.7"),
              "secp384r1": (384, "1.3.132.0.34"),
              "secp521r1": (521, "1.3.132.0.35")}
    if args.curve not in curves:
        raise SystemExit("unsupported curve %r" % args.curve)
    size, curve_oid = curves[args.curve]
    point = bytes.fromhex(args.point.lower().removeprefix("0x"))
    if point[0] != 0x04 or len(point) != 1 + 2 * ((size + 7) // 8):
        raise SystemExit("EC point is not an uncompressed %s point (%d bytes)"
                         % (args.curve, len(point)))
    spki = der_tlv(TAG_SEQUENCE, der_tlv(
        TAG_SEQUENCE, der_oid("1.2.840.10045.2.1") + der_oid(curve_oid))
        + der_bit_string(point))
    # Prove the point is on the curve before anyone signs with this key.
    serialization.load_der_public_key(spki)
    with open(args.out, "wb") as fh:
        fh.write(spki)
    print("wrote %s (%s, %d bytes)" % (args.out, args.curve, len(spki)))


def cmd_self_sign_root(args) -> None:
    signer = build_signer(args)
    subject = _name_from_cnf(args.cnf, args.dn_section)
    exts = _parse_openssl_extensions(args.cnf, args.extensions)
    ski = x509.SubjectKeyIdentifier.from_public_key(signer.public_key)
    resolved = _resolve_extensions(exts, signer.public_key, ski)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(signer.public_key)
        .serial_number(_serial(args.serial))
        .not_valid_before(_now(-1))
        .not_valid_after(_now(args.days))
    )
    for ext, critical in resolved:
        builder = builder.add_extension(ext, critical)

    template = builder.sign(_placeholder_key(signer.alg), signer.alg.hash_alg) \
        .public_bytes(serialization.Encoding.DER)
    tbs = _tbs_of(template)
    signature = signer.sign_digest(signer.alg.digest(tbs))
    der = splice(template, signer.alg, signature)

    cert = x509.load_der_x509_certificate(der)
    if cert.tbs_certificate_bytes != tbs:
        raise SystemExit("root: spliced TBS differs from signed TBS")
    verify_signature(signer.public_key, signature, tbs, signer.alg)
    print("root CA: subject=%s" % cert.subject.rfc4514_string())
    print("root CA: serial=%s sha256=%s" % (
        hex(cert.serial_number),
        cert.fingerprint(hashes.SHA256()).hex()))
    _write_pem(der, "certificate", args.out, args.also_der)


def cmd_create_intermediate_csr(args) -> None:
    signer = build_signer(args)
    subject = _name_from_cnf(args.cnf, args.dn_section)
    exts = _parse_openssl_extensions(args.cnf, args.extensions)
    issuer_ski = None
    if args.issuer_cert:
        with open(args.issuer_cert, "rb") as fh:
            issuer_ski = x509.load_pem_x509_certificate(fh.read()) \
                .extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value
    resolved = _resolve_extensions(exts, signer.public_key, issuer_ski)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    for ext, critical in resolved:
        builder = builder.add_extension(ext, critical)

    template = builder.sign(_placeholder_key(signer.alg), signer.alg.hash_alg) \
        .public_bytes(serialization.Encoding.DER)
    outer = list(der_children(template))
    cri = list(der_children(outer[0][1]))
    if len(cri) != 4:
        raise SystemExit("CSR: CertificationRequestInfo has %d elements" % len(cri))
    version_raw, subject_raw, _spki, attributes_raw = (c[1] for c in cri)
    new_cri = der_tlv(TAG_SEQUENCE, version_raw + subject_raw
                      + signer.public_key_der() + attributes_raw)
    signature = signer.sign_digest(signer.alg.digest(new_cri))
    der = assemble(new_cri, signer.alg, signature)

    csr = x509.load_der_x509_csr(der)
    verify_signature(signer.public_key, signature, csr.tbs_certrequest_bytes,
                     signer.alg)
    if csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo) != signer.public_key_der():
        raise SystemExit("CSR: embedded public key is not the signer's key")
    print("csr: subject=%s sha256=%s" % (
        csr.subject.rfc4514_string(),
        cert_fingerprint(csr)))
    _write_pem(der, "csr", args.out, args.also_der)


def cmd_sign_csr(args) -> None:
    signer = build_signer(args)
    with open(args.issuer_cert, "rb") as fh:
        issuer = x509.load_pem_x509_certificate(fh.read())
    with open(args.csr, "rb") as fh:
        csr = x509.load_pem_x509_csr(fh.read())

    # Proof of possession: never issue for a CSR whose signature does not check.
    try:
        verify_signature(csr.public_key(), csr.signature,
                         csr.tbs_certrequest_bytes,
                         _alg_from_csr(csr))
    except Exception as exc:  # noqa: BLE001 - any failure means do not issue
        raise SystemExit("CSR signature is invalid (%s) — refusing to issue"
                         % (str(exc) or type(exc).__name__))

    exts = _parse_openssl_extensions(args.cnf, args.extensions)
    issuer_ski = issuer.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value
    resolved = _resolve_extensions(exts, csr.public_key(), issuer_ski)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer.subject)
        .public_key(csr.public_key())
        .serial_number(_serial(args.serial))
        .not_valid_before(_now(-1))
        .not_valid_after(_now(args.days))
    )
    for ext, critical in resolved:
        builder = builder.add_extension(ext, critical)

    template = builder.sign(_placeholder_key(signer.alg), signer.alg.hash_alg) \
        .public_bytes(serialization.Encoding.DER)
    tbs = _tbs_of(template)
    signature = signer.sign_digest(signer.alg.digest(tbs))
    der = splice(template, signer.alg, signature)

    cert = x509.load_der_x509_certificate(der)
    if cert.tbs_certificate_bytes != tbs:
        raise SystemExit("certificate: spliced TBS differs from signed TBS")
    verify_signature(signer.public_key, signature, tbs, signer.alg)
    print("issued: subject=%s" % cert.subject.rfc4514_string())
    print("issued: issuer=%s serial=%s" % (cert.issuer.rfc4514_string(),
                                           hex(cert.serial_number)))
    print("issued: sha256=%s" % cert.fingerprint(hashes.SHA256()).hex())
    _write_pem(der, "certificate", args.out, args.also_der)


def cmd_sign_leaf_csr(args) -> None:
    signer = build_signer(args)
    with open(args.issuer_cert, "rb") as fh:
        issuer = x509.load_pem_x509_certificate(fh.read())
    with open(args.csr, "rb") as fh:
        csr = x509.load_pem_x509_csr(fh.read())
    try:
        verify_signature(csr.public_key(), csr.signature,
                         csr.tbs_certrequest_bytes, _alg_from_csr(csr))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit("CSR signature is invalid (%s) — refusing to issue"
                         % (str(exc) or type(exc).__name__))

    issuer_ski = issuer.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value
    # IAM Roles Anywhere contract for workload certificates.
    extensions = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=False, crl_sign=False,
                       encipher_only=False, decipher_only=False), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_ski), False),
    ]
    sans = []
    if args.san_dns:
        sans += [x509.DNSName(v) for v in args.san_dns]
    if args.san_uri:
        sans += [x509.UniformResourceIdentifier(v) for v in args.san_uri]
    if sans:
        extensions.append((x509.SubjectAlternativeName(sans), False))

    serial = _serial(args.serial)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(_now(-1))
        .not_valid_after(_now(args.days))
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical)

    template = builder.sign(_placeholder_key(signer.alg), signer.alg.hash_alg) \
        .public_bytes(serialization.Encoding.DER)
    tbs = _tbs_of(template)
    signature = signer.sign_digest(signer.alg.digest(tbs))
    der = splice(template, signer.alg, signature)

    cert = x509.load_der_x509_certificate(der)
    if cert.tbs_certificate_bytes != tbs:
        raise SystemExit("certificate: spliced TBS differs from signed TBS")
    verify_signature(signer.public_key, signature, tbs, signer.alg)
    print("issued leaf: subject=%s" % cert.subject.rfc4514_string())
    print("issued leaf: serial=%s not_after=%s" % (
        hex(cert.serial_number), cert.not_valid_after_utc.isoformat()))
    _write_pem(der, "certificate", args.out, args.also_der)
    print("serial_hex=0x%x" % cert.serial_number)


def cmd_generate_crl(args) -> None:
    signer = build_signer(args)
    with open(args.issuer_cert, "rb") as fh:
        issuer = x509.load_pem_x509_certificate(fh.read())
    issuer_ski = issuer.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value

    revoked = []
    if args.revoked_file:
        with open(args.revoked_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        entries = payload["revoked"] if isinstance(payload, dict) else payload
        for entry in entries:
            serial = entry["serial"] if isinstance(entry, dict) else entry
            when = entry.get("revoked_at") if isinstance(entry, dict) else None
            reason = entry.get("reason") if isinstance(entry, dict) else None
            record = x509.RevokedCertificateBuilder().serial_number(
                _serial(serial)).revocation_date(
                _parse_time(when) if when else _now(-1))
            if reason:
                flag = getattr(x509.ReasonFlags, reason.lower(), None)
                if flag is None:
                    raise SystemExit("unknown CRL reason %r" % reason)
                record = record.add_extension(x509.CRLReason(flag), False)
            revoked.append(record.build())

    crl_number = args.crl_number or int(_dt.datetime.now().timestamp())
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(_now(-1))
        .next_update(_now(args.days))
        .add_extension(x509.CRLNumber(crl_number), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_ski), False)
    )
    for record in revoked:
        builder = builder.add_revoked_certificate(record)

    template = builder.sign(_placeholder_key(signer.alg), signer.alg.hash_alg) \
        .public_bytes(serialization.Encoding.DER)
    tbs = _tbs_of(template)
    signature = signer.sign_digest(signer.alg.digest(tbs))
    der = splice(template, signer.alg, signature)

    crl = x509.load_der_x509_crl(der)
    if crl.tbs_certlist_bytes != tbs:
        raise SystemExit("crl: spliced TBS differs from signed TBS")
    verify_signature(signer.public_key, signature, tbs, signer.alg)
    print("crl: issuer=%s number=%d revoked=%d next_update=%s" % (
        crl.issuer.rfc4514_string(), crl_number, len(revoked),
        crl.next_update_utc.isoformat()))
    print("crl: sha256=%s" % crl.fingerprint(hashes.SHA256()).hex())
    _write_pem(der, "crl", args.out, True)

    if args.trust_anchor_arn:
        import_crl(args, der, crl_number, len(revoked))


def import_crl(args, der: bytes, crl_number: int, revoked_count: int) -> None:
    import boto3

    client = boto3.client("rolesanywhere", region_name=args.region)
    name = args.crl_name or "crl-%s" % _dt.datetime.now().strftime("%Y%m%dT%H%M%SZ")
    persisted = x509.load_der_x509_crl(der).public_bytes(serialization.Encoding.PEM)
    resp = client.import_crl(
        name=name,
        # ImportCrl documents PEM as the accepted encoding ("a CRL must be in
        # PEM format"); the signature itself is over the DER TBSCertList.
        crlData=persisted,
        trustAnchorArn=args.trust_anchor_arn,
        enabled=True,
    )
    crl_id = resp["crl"]["crlId"]
    detail = client.get_crl(crlId=crl_id)["crl"]
    if not detail.get("enabled"):
        raise SystemExit("imported CRL %s is not enabled" % crl_id)
    print("imported crl: id=%s arn=%s enabled=%s" % (
        crl_id, detail.get("crlArn"), detail.get("enabled")))
    print("imported crl: name=%s number=%d revoked=%d" % (
        name, crl_number, revoked_count))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _alg_from_csr(csr) -> SigAlg:
    oid = csr.signature_algorithm_oid.dotted_string
    for alg in SIG_ALGS.values():
        if alg.oid == oid:
            return alg
    raise SystemExit("unsupported CSR signature algorithm OID %s" % oid)


def cert_fingerprint(obj) -> str:
    return hashlib.sha256(obj.public_bytes(serialization.Encoding.DER)).hexdigest()


def _serial(value) -> int:
    if value is None:
        return x509.random_serial_number()
    text = str(value).strip()
    number = int(text, 16) if text.lower().startswith("0x") else int(text)
    if number <= 0:
        raise SystemExit("serial must be positive")
    return number


def _parse_time(value: str) -> _dt.datetime:
    text = value.replace("Z", "+00:00")
    parsed = _dt.datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)


def build_signer(args) -> Signer:
    if args.signer == "kms":
        if not args.kms_key_id:
            raise SystemExit("--kms-key-id is required with --signer kms")
        return KmsSigner(args.kms_key_id, args.region)
    if args.signer == "hsm":
        if not args.hsm_key_label or not args.hsm_public_key:
            raise SystemExit(
                "--hsm-key-label and --hsm-public-key are required with --signer hsm")
        return HsmSigner(args.hsm_key_label, args.hsm_public_key, args.hsm_curve,
                         args.hsm_cli, args.hsm_pin, args.cluster_id)
    if args.signer == "local":
        if not args.local_key:
            raise SystemExit("--local-key is required with --signer local")
        return LocalSigner(args.local_key)
    raise SystemExit("unknown signer %r" % args.signer)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue Roles Anywhere X.509 artifacts with KMS or CloudHSM keys.")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--signer", required=True, choices=["kms", "hsm", "local"])
        p.add_argument("--region", default=os.environ.get("AWS_REGION"))
        p.add_argument("--kms-key-id")
        p.add_argument("--hsm-key-label")
        p.add_argument("--hsm-public-key", help="SPKI DER/PEM rebuilt from the HSM EC point")
        p.add_argument("--hsm-curve", default="secp384r1")
        p.add_argument("--hsm-cli", default=os.environ.get(
            "CLOUDHSM_CLI", "/opt/cloudhsm/bin/cloudhsm-cli"))
        p.add_argument("--hsm-pin", help="defaults to $CLOUDHSM_PIN (user:password)")
        p.add_argument("--cluster-id")
        p.add_argument("--local-key", help="TESTING ONLY private key file")
        p.add_argument("--serial")
        p.add_argument("--also-der", action="store_true")
        p.add_argument("--json", action="store_true", help="machine-readable summary")

    p = sub.add_parser("spki-from-point",
                       help="rebuild SubjectPublicKeyInfo from an HSM EC point")
    p.add_argument("--curve", default="secp384r1")
    p.add_argument("--point", required=True, help="hex, e.g. 0x04... from cloudhsm-cli")
    p.add_argument("--out", required=True)

    p = sub.add_parser("self-sign-root", help="create the self-signed Root CA")
    common(p)
    p.add_argument("--cnf", required=True)
    p.add_argument("--dn-section", default="root_dn")
    p.add_argument("--extensions", default="v3_root_ca")
    p.add_argument("--days", type=int, default=3650)
    p.add_argument("--out", required=True)

    p = sub.add_parser("create-intermediate-csr",
                       help="CSR for the KMS Intermediate CA key")
    common(p)
    p.add_argument("--cnf", required=True)
    p.add_argument("--dn-section", default="intermediate_dn")
    p.add_argument("--extensions", default="v3_intermediate_ca")
    p.add_argument("--issuer-cert", help="Root CA PEM, for the AKI extension")
    p.add_argument("--out", required=True)

    p = sub.add_parser("sign-csr", help="issue a certificate for a CSR")
    common(p)
    p.add_argument("--cnf", required=True)
    p.add_argument("--extensions", required=True)
    p.add_argument("--issuer-cert", required=True)
    p.add_argument("--csr", required=True)
    p.add_argument("--days", type=int, default=1825)
    p.add_argument("--out", required=True)

    p = sub.add_parser("sign-leaf-csr", help="issue a clientAuth workload leaf")
    common(p)
    p.add_argument("--issuer-cert", required=True)
    p.add_argument("--csr", required=True)
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--san-dns", action="append")
    p.add_argument("--san-uri", action="append")
    p.add_argument("--out", required=True)

    p = sub.add_parser("generate-crl", help="build a DER CRL and import it")
    common(p)
    p.add_argument("--issuer-cert", required=True)
    p.add_argument("--revoked-file", help="JSON: [{\"serial\":\"0x1f\",...}]")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--crl-number", type=int)
    p.add_argument("--trust-anchor-arn")
    p.add_argument("--crl-name")
    p.add_argument("--out", required=True)
    return parser


def main(argv) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "spki-from-point": cmd_spki_from_point,
        "self-sign-root": cmd_self_sign_root,
        "create-intermediate-csr": cmd_create_intermediate_csr,
        "sign-csr": cmd_sign_csr,
        "sign-leaf-csr": cmd_sign_leaf_csr,
        "generate-crl": cmd_generate_crl,
    }
    handlers[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
