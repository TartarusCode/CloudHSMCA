#!/bin/bash
# =============================================================================
# Evaluates the module's variable-only locals the way `terraform plan` does.
#
# `terraform validate` never evaluates locals, so a local that raises only when
# it is actually computed (a filesystem call on an empty path, a bad conditional,
# a missing map key) passes every gate and fails at the first plan. This harness
# exists because of one of those: `fileexists("")` raising "'.' is a directory,
# not a file" on the default CRL path, which 1.9.x reported and 1.17 tolerated.
#
# Locals that read a resource attribute or a data source cannot be evaluated
# without state (the state machine definition reads the trust anchor id, the SSM
# paths of the bucket, the AMI), so they are out of scope; `terraform plan` is
# the only test for those.
#
# One expression per variable set: `terraform console` starts every provider in
# the configuration (~7 s with aws alone), so each set is a single jsonencode
# object compared in one pass.
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

# vpc_id / private_subnet_ids / availability_zone have no defaults: they are the
# only inputs a caller must supply.
BASE="-var vpc_id=vpc-0123456789abcdef0 -var private_subnet_ids=[\"subnet-0123456789abcdef0\"] -var availability_zone=us-west-2a"

console() { # console <var args...> < expression on stdin
  terraform -chdir="$MODULE" console "$@"
}

fail=0

# snapshot <label> <var args> <jsonencode object> <expected JSON object>
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
        print(f"  {label:<14} {key:<28} -> {json.dumps(got)[:60]}")
sys.exit(bad)
PY
}

echo "defaults (auto_bootstrap off, nothing required beyond the network):"
snapshot defaults "$BASE" \
  '{module_tag = local.module_tag, tags = local.tags, auto_bootstrap = var.auto_bootstrap, ssm_ca_bundle_pem = local.ssm_ca_bundle_pem, ssm_intermediate_ca_pem = local.ssm_intermediate_ca_pem, signing_algorithm = local.ca_signing_algorithm, workload_profiles = var.workload_profiles}' \
  "{\"module_tag\": \"cloudhsmca\", \"tags\": {\"Module\": \"cloudhsmca\", \"Tier\": \"root-of-trust\"}, \"auto_bootstrap\": false, \"ssm_ca_bundle_pem\": \"/corp-pki/pki/ca_bundle.pem\", \"ssm_intermediate_ca_pem\": \"/corp-pki/pki/intermediate_ca.pem\", \"signing_algorithm\": \"ECDSA_SHA_384\", \"workload_profiles\": {}}"

echo
echo "auto_bootstrap = true (the turnkey path is a variable, not a second module):"
snapshot auto-bootstrap "$BASE -var auto_bootstrap=true" \
  '{auto_bootstrap = var.auto_bootstrap, module_tag = local.module_tag}' \
  '{"auto_bootstrap": true, "module_tag": "cloudhsmca"}'

echo
echo "the Module tag overrides a caller-supplied Module, so Cost Explorer stays clean:"
snapshot tag-override "$BASE -var tags={\"Module\":\"legacy\",\"Team\":\"sec\"}" \
  '{tags = local.tags}' \
  '{"tags": {"Module": "cloudhsmca", "Team": "sec", "Tier": "root-of-trust"}}'

echo
echo "variable validation (one process: console reports every invalid variable it evaluates):"
# One invocation, not one per variable: console evaluates all the variables an
# expression references and prints a separate "Invalid value for variable" for
# each. The exit status is not a gate (console exits 0), so match the messages.
rejected=$(
  printf 'jsonencode({a = var.name, b = var.root_key_curve, c = var.object_lock_mode, d = var.workload_profiles})\n' \
    | console -var vpc_id=vpc-1 -var 'private_subnet_ids=["s-1"]' -var availability_zone=us-west-2a \
      -var name=Bad_Name \
      -var root_key_curve=secp999r1 \
      -var object_lock_mode=WORM \
      -var 'workload_profiles={bad={session_duration_seconds=60}}' 2>&1 || true
)
for want in 'must be 2-24 chars' 'root_key_curve must be' 'object_lock_mode must be' 'session_duration_seconds must be'; do
  if grep -qF "$want" <<<"$rejected"; then
    printf '  rejected %-34s -> ok\n' "$want"
  else
    echo "FAIL: no validation message containing '$want'; console said:" >&2
    printf '%s\n' "$rejected" >&2
    fail=1
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "MODULE SMOKE: FAIL" >&2
  exit 1
fi
echo "MODULE SMOKE: PASS"
