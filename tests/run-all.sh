#!/bin/bash
# Runs every offline harness for the module. No AWS account, no HSM, no
# credentials.
#
#   tests/module   — the variable-only locals evaluated the way plan does, both
#                    auto_bootstrap paths, the Module tag, the validations
#   tests/lambda   — the CRL handler extracted from crl_issuer_lambda.tf, signed
#                    with a real P-384 key and verified with openssl
#   tests/crypto   — kms_ca_tool.py: root, CSR, Intermediate, leaf, CRL, plus the
#                    refusal paths
#   tests/ceremony — hsm_ceremony.sh.tftpl rendered by Terraform and executed
#                    against a stub cloudhsm-cli that really signs
#   tests/asl_invariants.py — the rendered state machine walked as a graph:
#                    cleanup on States.ALL, cause preservation, SSM readiness,
#                    the backup gate, and the activation tail
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
run "crypto (kms_ca_tool.py)" bash "$HERE/crypto/test_kms_ca_tool.sh" "$MODULE"
run "ceremony (hsm_ceremony.sh)" bash "$HERE/ceremony/run.sh" "$MODULE"
run "asl invariants" python3 "$HERE/asl_invariants.py" "$MODULE"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL HARNESSES PASSED"
else
  echo "ONE OR MORE HARNESSES FAILED" >&2
fi
exit "$fail"
