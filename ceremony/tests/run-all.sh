#!/bin/bash
# Runs every harness for the ceremony stack. No AWS account, no HSM.
#
#   tests/asl_invariants.py — the ASL rendered by Terraform, walked as a graph:
#                             cleanup on States.ALL, cause preservation, SSM
#                             readiness, bootstrap/rotation, backup proof.
#   tests/crypto            — kms_ca_tool.py chain: root, CSR, intermediate,
#                             leaf, CRL, plus the refusal paths.
#   tests/ceremony          — hsm_ceremony.sh.tftpl rendered by Terraform and
#                             executed against a stub cloudhsm-cli, AWS CLI and
#                             KMS. This is the script the workflow runs.
#
# usage: tests/run-all.sh [stack-dir]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STACK="${1:-$(cd "$HERE/.." && pwd)}"
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

run "asl invariants" python3 "$HERE/asl_invariants.py" "$STACK"
run "crypto (kms_ca_tool.py)" bash "$HERE/crypto/test_kms_ca_tool.sh" "$STACK"
run "ceremony (hsm_ceremony.sh)" bash "$HERE/ceremony/run.sh" "$STACK"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL CEREMONY HARNESSES PASSED"
else
  echo "ONE OR MORE CEREMONY HARNESSES FAILED" >&2
fi
exit "$fail"
