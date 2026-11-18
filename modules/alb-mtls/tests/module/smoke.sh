#!/bin/bash
# =============================================================================
# Evaluates the ALB mTLS module's variable-only locals the way `terraform plan`
# does, and checks the two rules the provider would otherwise only report as an
# opaque API error at apply time:
#
#   * the S3 prefix derives from the CA name unless one is given;
#   * an ELBv2 trust store name is capped at 32 characters.
#
# Locals that read a resource attribute (the object version, the trust store
# ARN) cannot be evaluated offline; `terraform plan` is the only test for those.
#
# usage: tests/module/smoke.sh [module-dir]
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="${1:-$(cd "$HERE/../.." && pwd)}"

if [ ! -d "$MODULE/.terraform/providers" ]; then
  echo "initialising $MODULE"
  terraform -chdir="$MODULE" init -backend=false -input=false -no-color >/dev/null
fi

# The contract is an input, so it has to be supplied; these are the fields the
# locals touch, with plausible values.
CONTRACT='{name="corp-pki",region="us-west-2",account_id="111122223333",partition="aws",cluster_id="cluster-abc",artifacts_bucket="corp-pki-pki-artifacts",artifacts_bucket_arn="arn:aws:s3:::corp-pki-pki-artifacts",intermediate_kms_key_arn="arn:aws:kms:us-west-2:111122223333:key/abc",intermediate_kms_key_alias="alias/corp-pki-intermediate-ca",intermediate_key_spec="ECC_NIST_P384",signing_algorithm="ECDSA_SHA_384",root_ca_ssm_param="/corp-pki/pki/root_ca.pem",intermediate_ca_ssm_param="/corp-pki/pki/intermediate_ca.pem",ca_bundle_ssm_param="/corp-pki/pki/ca_bundle.pem",ceremony_state_ssm_param="/corp-pki/pki/ceremony/state",event_bus_name="default",event_source="cloudhsmca.pki",event_detail_type="CAChainPublished",state_machine_arn="arn:aws:states:us-west-2:111122223333:stateMachine:corp-pki-ceremony",log_group_name="/aws/states/corp-pki-ceremony"}'

BASE="-var ca_contract=$CONTRACT"

console() { # console <var args...> < expression on stdin
  terraform -chdir="$MODULE" console "$@"
}

fail=0

snapshot() { # snapshot <label> <var args> <jsonencode object> <expected JSON object>
  local label="$1" varargs="$2" expr="$3" want="$4" out
  # shellcheck disable=SC2086
  if ! out=$(printf 'jsonencode(%s)\n' "$expr" | console $varargs 2>&1); then
    echo "FAIL: $label raised an error:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  python3 - "$label" "$out" "$want" <<'PY' || fail=1
import json, sys

label, raw, want_raw = sys.argv[1], sys.argv[2], sys.argv[3]
value = raw
for _ in range(4):
    try:
        value = json.loads(value)
    except ValueError:
        break
    if isinstance(value, dict):
        break
if not isinstance(value, dict):
    print(f"FAIL: {label} did not evaluate to an object: {raw!r}", file=sys.stderr)
    sys.exit(1)

bad = 0
for key, expected in json.loads(want_raw).items():
    got = value.get(key, "<missing>")
    if got != expected:
        print(f"FAIL: {label}: {key} -> {got!r}, expected {expected!r}", file=sys.stderr)
        bad = 1
    else:
        print(f"  {label:<12} {key:<22} -> {json.dumps(got)[:56]}")
sys.exit(bad)
PY
}

echo "defaults (prefix and trust store name derive from the CA name):"
snapshot defaults "$BASE" \
  '{name = local.name, prefix = local.prefix, bundle_key = local.bundle_key, crl_key = local.crl_key, trust_store_name = local.trust_store_name, sync_lambda_name = local.sync_lambda_name, tags = local.tags}' \
  '{"name": "corp-pki", "prefix": "alb-mtls/corp-pki", "bundle_key": "alb-mtls/corp-pki/ca_bundle.pem", "crl_key": "alb-mtls/corp-pki/crl.pem", "trust_store_name": "corp-pki-alb-mtls", "sync_lambda_name": "corp-pki-alb-mtls-sync", "tags": {"Ca": "corp-pki", "Consumer": "alb-mtls", "Module": "cloudhsmca"}}'

echo
echo "an explicit name moves the prefix, not the trust store name:"
snapshot override "$BASE -var name=payments -var trust_store_name=payments-mtls" \
  '{prefix = local.prefix, trust_store_name = local.trust_store_name, sync_lambda_name = local.sync_lambda_name}' \
  '{"prefix": "alb-mtls/payments", "trust_store_name": "payments-mtls", "sync_lambda_name": "corp-pki-alb-mtls-sync"}'

echo
echo "the Lambda role keeps the <ca_name>- prefix the CA key policy matches on:"
snapshot role-name "$BASE -var name=payments" \
  '{sync_lambda_name = local.sync_lambda_name}' \
  '{"sync_lambda_name": "corp-pki-alb-mtls-sync"}'

echo
echo "variable validation (one process: console reports every invalid variable it evaluates):"
rejected=$(
  printf 'jsonencode({a = var.name, b = var.ca_contract.intermediate_kms_key_arn})\n' \
    | console -var name=Bad_Name -var "ca_contract=$(sed 's|arn:aws:kms:us-west-2:111122223333:key/abc|not-an-arn|' <<<"$CONTRACT")" 2>&1 || true
)
for want in 'must be empty or 2-24 chars' 'must be a KMS key ARN'; do
  if grep -qF "$want" <<<"$rejected"; then
    printf '  rejected %-34s -> ok\n' "$want"
  else
    echo "FAIL: no validation message containing '$want'; console said:" >&2
    printf '%s\n' "$rejected" >&2
    fail=1
  fi
done

echo
echo "the 32-character trust store name limit is a precondition on the resource:"
if grep -q 'length(local.trust_store_name) <= 32' "$MODULE/main.tf"; then
  printf '  %-40s -> ok\n' "precondition present"
else
  echo "FAIL: main.tf has no 32-character precondition on the trust store name" >&2
  fail=1
fi

echo "the placeholder is public-only (no signing key in Terraform state):"
if grep -q 'resource "tls_private_key"' "$MODULE/main.tf"; then
  echo "FAIL: a TLS private key is still generated into state" >&2
  fail=1
elif grep -qF 'file("${path.module}/placeholder_ca.crt")' "$MODULE/main.tf" \
     && [ -s "$MODULE/placeholder_ca.crt" ] \
     && grep -q 'BEGIN CERTIFICATE' "$MODULE/placeholder_ca.crt"; then
  printf '  %-40s -> ok\n' "static public PEM, no private key"
else
  echo "FAIL: placeholder bundle is not the checked-in public PEM" >&2
  fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "ALB-MTLS SMOKE: FAIL" >&2
  exit 1
fi
echo "ALB-MTLS SMOKE: PASS"
