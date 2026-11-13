#!/bin/bash
# Runs this module's offline harnesses. No AWS account needed.
#
#   tests/module  — evaluates the variable-only locals the way `terraform plan`
#                   does (the CRL-path cases, the variable validations).
#   tests/lambda  — the CRL handler extracted from crl_issuer_lambda.tf, signed
#                   with a real P-384 key and verified with openssl.
#
# The CA tooling (chain, CRL signing, the CloudHSM ceremony) lives in
# modules/pki-ceremony and is tested there.
#
# usage: tests/run-all.sh [module-dir]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="${1:-$(cd "$HERE/.." && pwd)}"
fail=0

run() {
  local name="$1"; shift
  echo
  echo "=============================================================="
  echo "== $name"
  echo "=============================================================="
  if "$@"; then
    echo "-- $name: PASS"
  else
    echo "-- $name: FAIL (exit $?)" >&2
    fail=1
  fi
}

run "module (locals evaluated like plan)" bash "$HERE/module/smoke.sh" "$MODULE"
run "lambda (crl handler)" python3 "$HERE/lambda/test_lambda.py" "$MODULE"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL HARNESSES PASSED"
else
  echo "ONE OR MORE HARNESSES FAILED" >&2
fi
exit "$fail"
