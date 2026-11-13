#!/bin/bash
# =============================================================================
# Evaluates the module's variable-only locals the way `terraform plan` does.
#
# `terraform validate` never evaluates locals, so a local that raises only when
# it is actually computed (fileexists(""), a bad conditional, a filesystem call
# on an empty path) passes every gate and fails at the first plan.
#
# The first two cases are a real defect this test was written for: crl_pem
# called fileexists("") when crl_pem_path was left empty, which Terraform 1.9.x
# reports as "'.' is a directory, not a file" while 1.17 tolerated it. The
# second case covers a path that does not exist yet.
#
# Locals that read a resource attribute cannot be evaluated without state, so
# they are out of scope here; `terraform plan` is the only test for those.
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

PHASE2='-var ceremony_mode=false'
PHASE1='-var ceremony_mode=true'
fail=0

echo "steady-state locals (defaults, empty crl_pem_path):"
eval_expr "$PHASE2" 'local.phase2' 'true' || fail=1
eval_expr "$PHASE2" 'local.crl_owned_by_awscc' 'true' || fail=1
eval_expr "$PHASE2" 'local.crl_pem' '""' || fail=1
eval_expr "$PHASE2" 'local.workload_profiles' 'tomap({})' || fail=1
eval_expr "$PHASE2" 'local.ca_signing_algorithm' '"ECDSA_SHA_384"' || fail=1
eval_expr "$PHASE2" 'local.root_digest' '"sha384"' || fail=1
eval_expr "$PHASE2" 'local.intermediate_digest' '"sha384"' || fail=1
eval_expr "$PHASE2" 'local.ssm_ca_bundle_pem' '"/corp-pki/pki/ca_bundle.pem"' || fail=1

echo
echo "a crl_pem_path that does not exist must not raise:"
eval_expr "$PHASE2 -var crl_pem_path=/nonexistent/crl.pem" 'local.crl_pem' '""' || fail=1

echo
echo "ceremony-mode locals:"
eval_expr "$PHASE1" 'local.phase2' 'false' || fail=1
eval_expr "$PHASE1" 'local.crl_owned_by_awscc' 'false' || fail=1
eval_expr "$PHASE1" 'local.crl_pem' '""' || fail=1

echo
echo "variable validation:"
check_rejected() { # check_rejected <var args> <expression> <label>
  local varargs="$1" expr="$2" label="$3" got
  # shellcheck disable=SC2086
  if got=$(printf '%s\n' "$expr" | console $varargs 2>&1); then
    echo "FAIL: $label was accepted ($got)" >&2
    return 1
  fi
  printf '  rejected %-28s -> ok\n' "$label"
}
check_rejected '-var ceremony_mode=false -var crl_management_mode=bogus' \
  'local.crl_owned_by_awscc' 'crl_management_mode=bogus' || fail=1
check_rejected '-var ceremony_mode=false -var name=Bad_Name' \
  'local.tags' 'name=Bad_Name' || fail=1
check_rejected '-var ceremony_mode=false -var intermediate_key_spec=ECC_SECG_P256K1' \
  'local.ca_signing_algorithm' 'unsupported key spec' || fail=1

echo
if [ "$fail" -ne 0 ]; then
  echo "MODULE SMOKE: FAIL" >&2
  exit 1
fi
echo "MODULE SMOKE: PASS"
