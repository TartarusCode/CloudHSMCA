#!/bin/bash
# =============================================================================
# Evaluates the module's variable-only locals the way `terraform plan` does.
#
# `terraform validate` never evaluates locals, so a local that raises only when
# it is actually computed (fileexists(""), a filesystem call on an empty path, a
# bad conditional) passes every gate and fails at the first plan.
#
# The CRL-path cases are a real defect this test was written for: crl_pem called
# fileexists("") when crl_pem_path was left empty, which Terraform 1.9.x reports
# as "'.' is a directory, not a file" while 1.17 tolerated it.
#
# Locals that read a resource attribute or a data source cannot be evaluated
# without state or a cloud call (trust_anchor_bundle comes from SSM), so they are
# out of scope here; `terraform plan` is the only test for those.
#
# One expression per variable set, not one per assertion: `terraform console`
# starts every provider in the configuration and aws + awscc cost ~7 s, so the
# original thirteen invocations made this harness 97 s. Each set is now a single
# jsonencode(...) object, compared in one pass.
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

KEY_ARN='arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'
BASE="-var intermediate_kms_key_arn=$KEY_ARN"

console() { # console <var args...> < expression on stdin
  terraform -chdir="$MODULE" console "$@"
}

fail=0

# snapshot <label> <var args> <jsonencode object> <expected JSON object>
# The first object is HCL as typed into the console; the expectation is JSON.
snapshot() {
  local label="$1" varargs="$2" expr="$3" want="$4" out
  # shellcheck disable=SC2086 # varargs is intentionally word-split
  if ! out=$(printf 'jsonencode(%s)\n' "$expr" | console $varargs 2>&1); then
    echo "FAIL: $label raised an error:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  # `console` prints the jsonencode result as a quoted string (quoted twice on
  # some 1.x releases), so decode until a dict comes out.
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
        print(f"  {label:<12} {key:<26} -> {json.dumps(got)[:40]}")
sys.exit(bad)
PY
}

echo "defaults (declarative CRL, empty crl_pem_path):"
snapshot defaults "$BASE" \
  '{crl_owned_by_awscc = local.crl_owned_by_awscc, crl_pem = local.crl_pem, workload_profiles = var.workload_profiles, ssm_ca_bundle_pem = local.ssm_ca_bundle_pem, ssm_intermediate_ca_pem = local.ssm_intermediate_ca_pem, name = var.name}' \
  '{"crl_owned_by_awscc": true, "crl_pem": "", "workload_profiles": {}, "ssm_ca_bundle_pem": "/corp-pki/pki/ca_bundle.pem", "ssm_intermediate_ca_pem": "/corp-pki/pki/intermediate_ca.pem", "name": "corp-pki"}'

echo
echo "lambda CRL ownership:"
snapshot lambda "$BASE -var crl_management_mode=lambda" \
  '{crl_owned_by_awscc = local.crl_owned_by_awscc, crl_pem = local.crl_pem}' \
  '{"crl_owned_by_awscc": false, "crl_pem": ""}'

echo
echo "a crl_pem_path that does not exist must not raise:"
snapshot missing "$BASE -var crl_pem_path=/nonexistent/crl.pem" \
  '{crl_pem = local.crl_pem}' \
  '{"crl_pem": ""}'

echo
echo "variable validation:"
check_rejected() { # check_rejected <var args> <expression> <label>
  local varargs="$1" expr="$2" label="$3" got
  # shellcheck disable=SC2086
  got=$(printf '%s\n' "$expr" | console $varargs 2>&1) || true
  # `terraform console` prints "Error: Invalid value for variable" and still
  # exits 0, so the exit status cannot be the gate here: match the error marker.
  # Validation also only runs for the variables an expression references, so the
  # expression has to touch the variable under test.
  if ! grep -qE 'Invalid value for variable|Error:' <<<"$got"; then
    echo "FAIL: $label was accepted ($got)" >&2
    return 1
  fi
  printf '  rejected %-30s -> ok\n' "$label"
}
check_rejected '-var intermediate_kms_key_arn=not-an-arn' \
  'var.intermediate_kms_key_arn' 'intermediate_kms_key_arn=not-an-arn' || fail=1
check_rejected "$BASE -var crl_management_mode=bogus" \
  'local.crl_owned_by_awscc' 'crl_management_mode=bogus' || fail=1
check_rejected "$BASE -var name=Bad_Name" \
  'local.tags' 'name=Bad_Name' || fail=1

echo
if [ "$fail" -ne 0 ]; then
  echo "MODULE SMOKE: FAIL" >&2
  exit 1
fi
echo "MODULE SMOKE: PASS"
