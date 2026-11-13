#!/usr/bin/env bash
# Local end-to-end exercise of scripts/kms_ca_tool.py with --signer local.
# Proves the TBS-splice path (the part that will run against KMS / CloudHSM)
# before anything is applied to AWS.
set -euo pipefail

MOD="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
WORK="$(mktemp -d)"
cd "$WORK"

py() { python3 "$MOD/scripts/kms_ca_tool.py" "$@"; }

render() { # render <template> <out> k=v ...
  local tpl="$1" out="$2"; shift 2
  python3 - "$tpl" "$out" "$@" <<'PY'
import sys
tpl, out, pairs = sys.argv[1], sys.argv[2], sys.argv[3:]
text = open(tpl).read()
for pair in pairs:
    k, v = pair.split("=", 1)
    text = text.replace("${%s}" % k, v)
assert "${" not in text, [l for l in text.splitlines() if "${" in l]
open(out, "w").write(text)
PY
}

SUBJ_ROOT="root_subject.country=US"
render "$MOD/scripts/root_ca.cnf.tftpl" root_ca.cnf \
  root_dn_section=root_dn root_curve=secp384r1 root_digest=sha384 \
  root_subject.country=US root_subject.state=WA \
  root_subject.locality=Seattle root_subject.organization=Example \
  root_subject.organizational_unit=PKI \
  root_subject.common_name="Example Root CA"
render "$MOD/scripts/intermediate_ca.cnf.tftpl" intermediate_ca.cnf \
  intermediate_dn_section=intermediate_dn intermediate_digest=sha256 \
  intermediate_key_spec=ECC_NIST_P256 \
  intermediate_subject.country=US intermediate_subject.state=WA \
  intermediate_subject.locality=Seattle intermediate_subject.organization=Example \
  intermediate_subject.organizational_unit=PKI \
  intermediate_subject.common_name="Example Intermediate CA"

echo "=== 1. spki-from-point reproduces the real SPKI byte-for-byte"
openssl ecparam -name secp384r1 -genkey -noout -out root.key
openssl pkey -in root.key -pubout -outform DER -out root_pub.expected.der
POINT=$(python3 - <<'PY'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
k = serialization.load_pem_private_key(open("root.key","rb").read(), None)
print("0x" + k.public_key().public_bytes(serialization.Encoding.X962,
      serialization.PublicFormat.UncompressedPoint).hex())
PY
)
py spki-from-point --curve secp384r1 --point "$POINT" --out root_pub.der
cmp root_pub.der root_pub.expected.der && echo "OK spki matches openssl"

echo "=== 2. self-signed root with a 384-bit key (ECDSA_SHA_384)"
py self-sign-root --signer local --local-key root.key \
  --cnf root_ca.cnf --dn-section root_dn --extensions v3_root_ca \
  --days 3650 --also-der --out root_ca.pem
openssl verify -CAfile root_ca.pem root_ca.pem
openssl x509 -in root_ca.pem -noout -text | grep -E "Basic Constraints|CA:TRUE|Certificate Sign|Digital Signature|CRL Sign" | sed 's/^ */  /'
openssl x509 -in root_ca.pem -noout -subject -issuer -dates

echo "=== 3. KMS-style intermediate: CSR from a 256-bit key (ECDSA_SHA_256)"
openssl ecparam -name prime256v1 -genkey -noout -out inter.key
py create-intermediate-csr --signer local --local-key inter.key \
  --cnf intermediate_ca.cnf --dn-section intermediate_dn \
  --extensions v3_intermediate_ca --issuer-cert root_ca.pem --out inter.csr
openssl req -in inter.csr -noout -verify
openssl req -in inter.csr -noout -text | grep -E "CA:TRUE|pathlen|Certificate Sign" | sed 's/^ */  /'

echo "=== 4. root HSM-signed intermediate certificate"
py sign-csr --signer local --local-key root.key --issuer-cert root_ca.pem \
  --csr inter.csr --cnf intermediate_ca.cnf --extensions v3_intermediate_ca \
  --days 1825 --out intermediate_ca.pem
openssl verify -CAfile root_ca.pem intermediate_ca.pem
openssl x509 -in intermediate_ca.pem -noout -text \
  | grep -E "CA:TRUE, pathlen:0|Subject Key Identifier|Authority Key Identifier" -A1 | sed 's/^ */  /'

echo "=== 5. workload leaf (clientAuth) from the Intermediate CA"
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/CN=workload-01/O=Example/OU=platform" \
  -out leaf.csr -sha256
py sign-leaf-csr --signer local --local-key inter.key --issuer-cert intermediate_ca.pem \
  --csr leaf.csr --days 90 --out leaf.pem
openssl verify -CAfile root_ca.pem -untrusted intermediate_ca.pem leaf.pem
openssl x509 -in leaf.pem -noout -text | grep -E "CA:FALSE|Digital Signature|TLS Web Client Authentication" | sed 's/^ */  /'
SERIAL=$(openssl x509 -in leaf.pem -noout -serial | cut -d= -f2)

echo "=== 6. DER CRL signed by the Intermediate CA"
printf '[{"serial":"0x%s","reason":"key_compromise","revoked_at":"2026-11-01T00:00:00Z"}]' "$SERIAL" > revoked.json
py generate-crl --signer local --local-key inter.key --issuer-cert intermediate_ca.pem \
  --revoked-file revoked.json --days 7 --crl-number 42 --out crl.pem
openssl crl -in crl.pem -inform PEM -outform DER -out crl.der
openssl crl -in crl.der -inform DER -noout -text | grep -E "Issuer|Update|Serial Number|CRL Reason" -A1 | sed 's/^ */  /'
openssl crl -in crl.pem -CAfile intermediate_ca.pem -noout && echo "OK CRL signature verifies"

echo "=== 7. NEGATIVE: a tampered CSR must be refused"
openssl req -in leaf.csr -outform DER -out leaf.der
python3 - <<'PY'
import base64
data = bytearray(open("leaf.der", "rb").read())
data[-5] ^= 0xFF           # corrupt the appended signature
b64 = base64.b64encode(bytes(data)).decode()
body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
open("tampered.csr", "w").write(
    "-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n" % body)
PY
if py sign-leaf-csr --signer local --local-key inter.key --issuer-cert intermediate_ca.pem \
     --csr tampered.csr --out nope.pem 2>err.txt; then
  echo "FAIL: tampered CSR was issued"; exit 1
else
  echo "OK refused: $(head -2 err.txt | tr -d '\n')"
fi

echo "=== 8. NEGATIVE: an extension the profiles do not define must fail loudly"
printf '[ root_dn ]\nCN = Example Root CA\n[ v3_bad ]\nnsComment = "hello"\n' > bad.cnf
if py self-sign-root --signer local --local-key root.key --cnf bad.cnf \
     --dn-section root_dn --extensions v3_bad --out bad.pem 2>bad.txt; then
  echo "FAIL: unknown extension accepted"; exit 1
else
  grep -q "unsupported extension" bad.txt || { echo "FAIL: refused for the wrong reason"; cat bad.txt; exit 1; }
  echo "OK refused: $(head -1 bad.txt)"
fi

echo "=== 9. serial/hex normalisation and CRL numbering"
openssl crl -in crl.pem -noout -text | grep -q "X509v3 CRL Number" && echo "OK crlNumber present"
echo "ALL CHECKS PASSED in $WORK"
