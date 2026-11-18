#!/bin/bash
# =============================================================================
# End-to-end harness for scripts/hsm_ceremony.sh.tftpl.
#
# Renders the real Terraform template, then runs the rendered script with:
#   * cloudhsm-cli  -> stub that really signs (base64 r||s, as SDK 5 returns)
#   * boto3/kms     -> stub backed by a local P-256 key
#   * aws           -> stub for ssm / cloudhsmv2 / s3api
#   * dnf, curl, systemctl, configure-cli, uv -> stubs
# Everything else is real: jq, openssl, the CA tool, both OpenSSL profiles.
#
# Proves: config parsing, HSM JSON extraction, EC-point -> SPKI, HSM signing of
# the Root and Intermediate certificates, the X.509 profile assertions, and the
# SSM/S3 publishing contract. No AWS account and no HSM are involved.
#
# usage: tests/ceremony/run.sh [module-dir]
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="${1:-$(cd "$HERE/../../modules/hsm-ca" && pwd)}"
HARNESS="$(mktemp -d)"
STUB="$HARNESS/stub"
export HARNESS STUB_DIR="$STUB"
mkdir -p "$STUB" "$HARNESS/pki" "$HARNESS/work" "$HARNESS/scripts" "$HARNESS/fakebin" "$HARNESS/cloudhsm-etc"
echo NOT_STARTED > "$STUB/state"
trap 'rm -rf "$HARNESS"' EXIT

# A separate commissioning CA claims the cluster. Its private key is served
# through the SSM stub; the certificate is public and goes into the config.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
  -keyout "$STUB/commissioning-key.pem" -out "$STUB/commissioning-ca.pem" \
  -sha384 -days 3650 -subj "/O=harness/CN=harness commissioning CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo "module: $MODULE"
echo "work:   $HARNESS"

# `terraform console` loads the module configuration, so its providers must be
# installed before the template can be rendered. Self-heal rather than making
# the operator remember: CI and a fresh clone both start with no .terraform.
if [ ! -d "$MODULE/.terraform/providers" ]; then
  echo "initialising $MODULE (providers are needed to render the template)"
  terraform -chdir="$MODULE" init -backend=false -input=false -no-color >/dev/null
fi

# --- stubs ------------------------------------------------------------------
for tool in dnf curl systemctl configure-cli; do
  cat > "$HARNESS/fakebin/$tool" <<EOF
#!/bin/bash
echo "\$0 \$*" >> "$STUB/\$(basename \$0).log"
# curl -o <file>: create it so the rpm install step has something to install
if [ "\$(basename \$0)" = curl ]; then
  prev=""; for a in "\$@"; do [ "\$prev" = "-o" ] && : > "\$a"; prev="\$a"; done
fi
exit 0
EOF
  chmod +x "$HARNESS/fakebin/$tool"
done

cat > "$HARNESS/fakebin/uv" <<EOF
#!/bin/bash
# uv venv <dir>: create a python that forwards to the real interpreter
if [ "\$1" = "venv" ]; then
  dir="\${!#}"
  mkdir -p "\$dir/bin"
  printf '#!/bin/bash\nexec python3 "\$@"\n' > "\$dir/bin/python"
  chmod +x "\$dir/bin/python"
fi
exit 0
EOF
chmod +x "$HARNESS/fakebin/uv"

cp "$HERE/bin/aws" "$HERE/bin/cloudhsm-cli" "$HARNESS/fakebin/"
cp -r "$HERE/pylib" "$HARNESS/pylib"
chmod +x "$HARNESS/fakebin/aws" "$HARNESS/fakebin/cloudhsm-cli"

# --- render the ceremony exactly as Terraform does ---------------------------
RENDERED="$HARNESS/work/rendered.sh"
python3 - "$MODULE" "$RENDERED" <<'PY'
import json, os, subprocess, sys

module, out_path = sys.argv[1], sys.argv[2]
cfg = {
    "name": "corp-pki", "region": "us-west-2", "cluster_id": "cluster-abc123",
    "hsm_ip": "10.0.1.5", "bucket": "corp-pki-artifacts",
    "kms_key_arn": "arn:aws:kms:us-west-2:111122223333:key/abc",
    "root_curve": "secp384r1", "root_digest": "sha384",
    "root_label": "root-ca-corp-pki",
    "public_key_der": "PKI/root_ca_pub.der", "root_validity_days": 3650,
    "inter_validity_days": 1825,
    "ssm_root_ca_pem": "/corp-pki/pki/root_ca.pem",
    "ssm_intermediate_pem": "/corp-pki/pki/intermediate_ca.pem",
    "ssm_ca_bundle_pem": "/corp-pki/pki/ca_bundle.pem",
    "ssm_ceremony_state": "/corp-pki/pki/ceremony/state",
    "ssm_admin_password": "/corp-pki/pki/ceremony/hsm-admin-password",
    "ssm_cu_password": "/corp-pki/pki/ceremony/hsm-cu-password",
    "s3_kms_ca_tool": "scripts/kms_ca_tool.py",
    "s3_root_ca_cnf": "scripts/root_ca.cnf",
    "s3_intermediate_cnf": "scripts/intermediate_ca.cnf",
    "cu_username": "pki-cu", "cloudhsm_cli_rpm": "https://example/rpm",
    "commissioning_ca_cert": open(os.path.join(os.environ["STUB_DIR"], "commissioning-ca.pem")).read(),
    "commissioning_key_ssm_param": "/corp-pki/pki/ceremony/commissioning-key",
    "commissioning_signed_cert": "",
    # The curl stub creates an empty RPM, whose SHA-256 is the well-known digest
    # of no bytes; the ceremony must verify it before installing.
    "cloudhsm_cli_rpm_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "uv_version": "0.5.11",
    "uv_installer_sha256": "",
    "s3_tool_version": "v1",
    "s3_root_cnf_version": "v1",
    "s3_inter_cnf_version": "v1",
}
expr = 'jsonencode(templatefile("scripts/hsm_ceremony.sh.tftpl", {ceremony_config = %s}))' % (
    json.dumps(json.dumps(cfg)))
res = subprocess.run(["terraform", "console"], cwd=module, input=expr,
                     capture_output=True, text=True)
if res.returncode != 0:
    sys.exit("terraform console failed: %s\n%s" % (res.stdout, res.stderr))


def decode_console_string(raw):
    """Terraform console quoted a string value one extra time in some releases."""
    body = raw.strip()
    for _ in range(3):
        try:
            nxt = json.loads(body)
        except json.JSONDecodeError:
            return body
        if not isinstance(nxt, str) or nxt == body:
            return body
        body = nxt
    return body


body = decode_console_string(res.stdout)
# Every $${...} in the template is a shell expansion and must still be one
# after rendering; the JSON document must have arrived intact.
assert '"cluster_id": "cluster-abc123"' in body, \
    "config JSON missing from render: %r" % body[:200]
open(out_path, "w").write(body)
print("rendered ceremony: %d bytes" % len(body))
PY

bash -n "$RENDERED" || { echo "FAIL: rendered ceremony is not valid bash" >&2; exit 1; }

# --- render the two OpenSSL profiles the same way ---------------------------
python3 - "$MODULE" "$HARNESS/scripts" <<'PY'
import json, subprocess, sys

module, out_dir = sys.argv[1], sys.argv[2]
root_subject = {"country": "US", "state": "Washington", "locality": "Seattle",
                "organization": "Example Corp",
                "organizational_unit": "Platform Security",
                "common_name": "Example Corp Root CA"}
vars_ = {
    "root_dn_section": "root_dn", "root_curve": "secp384r1",
    "root_digest": "sha384", "root_subject": root_subject,
    "intermediate_dn_section": "intermediate_dn", "intermediate_digest": "sha256",
    "intermediate_key_spec": "ECC_NIST_P256",
    "intermediate_subject": dict(root_subject,
                                 common_name="Example Corp Issuing CA"),
}
for tpl, name in (("scripts/root_ca.cnf.tftpl", "root_ca.cnf"),
                  ("scripts/intermediate_ca.cnf.tftpl", "intermediate_ca.cnf")):
    expr = "jsonencode(templatefile(%s, %s))" % (json.dumps(tpl), json.dumps(vars_))
    res = subprocess.run(["terraform", "console"], cwd=module, input=expr,
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit("terraform console failed for %s:\n%s\n%s"
                 % (tpl, res.stdout, res.stderr))
    # The console quotes a string value once more in some releases (1.9.x);
    # decode until the value stops being a quoted JSON string.
    body = res.stdout.strip()
    for _ in range(3):
        try:
            nxt = json.loads(body)
        except json.JSONDecodeError:
            break
        if not isinstance(nxt, str) or nxt == body:
            break
        body = nxt
    assert "${" not in body, [l for l in body.splitlines() if "${" in l]
    assert body.lstrip().startswith("#"), body[:80]
    open("%s/%s" % (out_dir, name), "w").write(body)
    print("rendered %s: %d bytes" % (name, len(body)))
PY

# --- point the fixed production paths at the sandbox ------------------------
sed -e "s#/opt/pki#$HARNESS/pki#g" \
    -e "s#/opt/cloudhsm/etc#$HARNESS/cloudhsm-etc#g" \
    -e "s#/opt/cloudhsm/bin/cloudhsm-cli#$HARNESS/fakebin/cloudhsm-cli#g" \
    -e "s#/opt/cloudhsm/bin/configure-cli#$HARNESS/fakebin/configure-cli#g" \
    -e "s#/var/log/pki-ceremony.log#$HARNESS/pki-ceremony.log#g" \
    -e "s#/var/lib/cloud/instance/user-data.txt#$HARNESS/user-data.txt#g" \
    -e "s#\"PKI/root_ca_pub.der\"#\"$HARNESS/pki/root_ca_pub.der\"#" \
    "$RENDERED" > "$STUB/ceremony.sh"

ln -sf "$MODULE/scripts/kms_ca_tool.py" "$HARNESS/scripts/kms_ca_tool.py"

# --- fake credentials and the KMS stand-in ---------------------------------
export PATH="$HARNESS/fakebin:$PATH"
export PYTHONPATH="$HARNESS/pylib"
export FAKE_KMS_KEY="$STUB/kms_ca_key.pem"
export FAKE_KMS_LOG="$STUB/kms-calls.log"
export CLOUDHSM_CLI="$HARNESS/fakebin/cloudhsm-cli"
openssl ecparam -name prime256v1 -genkey -noout -out "$FAKE_KMS_KEY"
: > "$HARNESS/user-data.txt"

echo
echo "=== running the ceremony script ==="
bash "$STUB/ceremony.sh"

echo
echo "=== independent verification (outside the script) ==="
cd "$HARNESS/pki"
openssl verify -CAfile root_ca.pem root_ca.pem
openssl verify -CAfile root_ca.pem intermediate_ca.pem
openssl x509 -in root_ca.pem -noout -subject -issuer -dates
openssl x509 -in root_ca.pem -noout -text | grep -E "CA:TRUE|Certificate Sign|Key Identifier" | sed 's/^ */  /'
openssl x509 -in intermediate_ca.pem -noout -text | grep -E "pathlen|Public Key Algorithm|Signature Algorithm" | sed 's/^ */  /'
echo "--- SSM writes ---"; cat "$STUB/ssm-puts.log"
echo "--- S3 writes ---";  cat "$STUB/s3-puts.log"
echo "--- final ceremony state: $(cat "$STUB/state") ---"
echo "--- HSM calls ---"; grep -E "generate-asymmetric|sign ecdsa" "$STUB/cloudhsm-cli.log" | cut -c1-110
echo "--- KMS calls ---"; cat "$STUB/kms-calls.log"

[ "$(cat "$STUB/state")" = "COMPLETE" ] || { echo "FAIL: ceremony state is not COMPLETE" >&2; exit 1; }

# --- claim scenario: a fresh cluster is UNINITIALIZED ----------------------
# This is the first apply's real starting point. The ceremony must sign the
# cluster CSR with the commissioning CA, call InitializeCluster, install the
# client trust anchor, and only then activate.
echo
echo "=== claim scenario: cluster starts UNINITIALIZED ==="
echo NOT_STARTED > "$STUB/state"
rm -f "$STUB/activated" "$STUB/claimed" "$STUB/initialize.log" \
      "$STUB/cluster.csr" "$STUB/cluster-csr-key.pem"
cd "$HARNESS"
rm -rf "$HARNESS/pki"; mkdir -p "$HARNESS/pki"
if ! HSM_STUB_UNINITIALIZED=1 bash "$STUB/ceremony.sh" > "$HARNESS/claim.log" 2>&1; then
  echo "FAIL: the ceremony did not complete on an UNINITIALIZED cluster" >&2
  tail -25 "$HARNESS/claim.log" >&2
  exit 1
fi
grep -q "claiming uninitialized cluster" "$HARNESS/claim.log" \
  || { echo "FAIL: the claim phase never ran" >&2; exit 1; }
grep -q "cluster claimed: INITIALIZED" "$HARNESS/claim.log" \
  || { echo "FAIL: the cluster never reached INITIALIZED" >&2; exit 1; }
[ -s "$STUB/initialize.log" ] \
  || { echo "FAIL: InitializeCluster was never called" >&2; exit 1; }
[ "$(cat "$STUB/state")" = "COMPLETE" ] \
  || { echo "FAIL: claim-run ceremony state is not COMPLETE" >&2; exit 1; }
openssl verify -CAfile "$STUB/commissioning-ca.pem" "$HARNESS/pki/cluster-cert.pem" >/dev/null \
  || { echo "FAIL: signed cluster certificate does not chain to the commissioning CA" >&2; exit 1; }
cmp -s "$STUB/commissioning-ca.pem" "$HARNESS/cloudhsm-etc/customerCA.crt" \
  || { echo "FAIL: the commissioning CA was not installed as the client trust anchor" >&2; exit 1; }
echo "claim verified: CSR signed, InitializeCluster called, trust anchor installed"

# --- supply-chain gate: a wrong RPM hash aborts before credentials ---------
echo
echo "=== supply-chain gate: wrong CLI RPM checksum ==="
sed '/cloudhsm_cli_rpm_sha256/ s/[0-9a-f]\{64\}/deadbeef/' \
  "$STUB/ceremony.sh" > "$STUB/ceremony-badhash.sh"
grep -q 'deadbeef' "$STUB/ceremony-badhash.sh" \
  || { echo "FAIL: could not inject a bad RPM hash into the rendered script" >&2; exit 1; }
echo NOT_STARTED > "$STUB/state"
: > "$STUB/aws.log"
if HSM_STUB_UNINITIALIZED=1 bash "$STUB/ceremony-badhash.sh" > "$HARNESS/badhash.log" 2>&1; then
  echo "FAIL: the ceremony installed a CLI RPM with a wrong checksum" >&2
  exit 1
fi
grep -q "CloudHSM CLI RPM checksum mismatch" "$HARNESS/badhash.log" \
  || { echo "FAIL: the checksum mismatch was not reported" >&2; tail -10 "$HARNESS/badhash.log" >&2; exit 1; }
if grep -q "get-parameter .*hsm-admin-password" "$STUB/aws.log"; then
  echo "FAIL: the ceremony read the admin password before verifying the CLI package" >&2
  exit 1
fi
echo "verified: bad RPM hash aborted before any credential read"

echo
echo "CEREMONY HARNESS: PASS"
