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

eval_expr() { # eval_expr "<var args>" <expression> <expected>
  local varargs="$1" expr="$2" want="$3" got
  # shellcheck disable=SC2086 # varargs is intentionally word-split
  if ! got=$(printf '%s\n' "$expr" | console $varargs 2>&1); then
    echo "FAIL: evaluating $expr raised an error:" >&2
    printf '%s\n' "$got" >&2
    return 1
  fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $expr evaluated to $got, expected $want" >&2
    return 1
  fi
  printf '  %-38s -> %s\n' "$expr" "${got:0:50}"
}

fail=0

echo "defaults (declarative CRL, empty crl_pem_path):"
eval_expr "$BASE" 'local.crl_owned_by_awscc' 'true' || fail=1
eval_expr "$BASE" 'local.crl_pem' '""' || fail=1
eval_expr "$BASE" 'var.workload_profiles' 'tomap({})' || fail=1
eval_expr "$BASE" 'local.ssm_ca_bundle_pem' '"/corp-pki/pki/ca_bundle.pem"' || fail=1
eval_expr "$BASE" 'local.ssm_intermediate_ca_pem' '"/corp-pki/pki/intermediate_ca.pem"' || fail=1

echo
echo "lambda CRL ownership:"
eval_expr "$BASE -var crl_management_mode=lambda" 'local.crl_owned_by_awscc' 'false' || fail=1
eval_expr "$BASE -var crl_management_mode=lambda" 'local.crl_pem' '""' || fail=1

echo
echo "a crl_pem_path that does not exist must not raise:"
eval_expr "$BASE -var crl_pem_path=/nonexistent/crl.pem" 'local.crl_pem' '""' || fail=1

echo
echo "variable validation:"
check_rejected() { # check_rejected <var args> <expression> <label>
  local varargs="$1" expr="$2" label="$3" got
  # shellcheck disable=SC2086
  got=$(printf '%s\n' "$expr" | console $varargs 2>&1) || true
  # `terraform console` prints "Error: Invalid value for variable" and still
  # exits 0, so the exit status cannot be the gate here: match the error marker.
  if ! grep -qE 'Invalid value for variable|Error:' <<<"$got"; then
    echo "FAIL: $label was accepted ($got)" >&2
    return 1
  fi
  printf '  rejected %-28s -> ok\n' "$label"
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
