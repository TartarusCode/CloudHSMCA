#!/bin/bash
# Runs the two offline harnesses for the ALB mutual-TLS consumer.
#
#   tests/module  — the variable-only locals the way plan computes them, plus the
#                   32-character trust store name rule
#   tests/lambda  — the sync Lambda extracted from sync_lambda.tf: activation
#                   (bundle to S3, ModifyTrustStore, CRL import), the scheduled
#                   skip before publication, the add-then-remove rotation order,
#                   and the CRL itself verified with openssl
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

run "module (alb-mtls locals evaluated like plan)" bash "$HERE/module/smoke.sh" "$MODULE"
run "lambda (activation + CRL rotation)" python3 "$HERE/lambda/test_lambda.py" "$MODULE"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL ALB-MTLS HARNESSES PASSED"
else
  echo "ONE OR MORE ALB-MTLS HARNESSES FAILED" >&2
fi
exit "$fail"
