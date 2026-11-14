#!/bin/bash
# Runs every offline harness for both modules. No AWS account, no HSM, no
# credentials.
#
#   tests/module   — modules/hsm-ca's variable-only locals the way plan computes
#                    them, both auto_bootstrap paths, the Module tag
#   tests/asl_invariants.py — modules/hsm-ca's rendered state machine: cleanup on
#                    States.ALL, cause preservation, SSM readiness, the backup
#                    gate, and the CAChainPublished fan-out
#   tests/crypto   — kms_ca_tool.py: root, CSR, Intermediate, leaf, CRL
#   tests/ceremony — hsm_ceremony.sh.tftpl rendered by Terraform and executed
#                    against a stub cloudhsm-cli that really signs
#   tests/lambda   — modules/roles-anywhere's Lambda: the CAChainPublished
#                    activation path, the scheduled refresh, the no-chain skip,
#                    and the CRL itself, verified with openssl
#
# usage: tests/run-all.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
HsmCa="$ROOT/modules/hsm-ca"
RolesAnywhere="$ROOT/modules/roles-anywhere"
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

run "module (hsm-ca locals evaluated like plan)" bash "$HERE/module/smoke.sh" "$HsmCa"
run "asl invariants (hsm-ca, no consumer coupling)" python3 "$HERE/asl_invariants.py" "$HsmCa"
run "crypto (kms_ca_tool.py)" bash "$HERE/crypto/test_kms_ca_tool.sh" "$HsmCa"
run "ceremony (hsm_ceremony.sh)" bash "$HERE/ceremony/run.sh" "$HsmCa"
run "lambda (activation + CRL refresh)" python3 "$HERE/lambda/test_lambda.py" "$RolesAnywhere"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL HARNESSES PASSED"
else
  echo "ONE OR MORE HARNESSES FAILED" >&2
fi
exit "$fail"
