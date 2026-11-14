#!/bin/bash
# =============================================================================
# verify_live_control_plane.sh — prove the AWS integration without an HSM
#
# The offline harnesses cannot reach four things: CreateTrustAnchor accepting a
# disabled placeholder, EventBridge delivering CAChainPublished to the consumer,
# the KMS key policy letting the consumer role sign, and Roles Anywhere accepting
# the CRL. This script exercises three of them against a deployed stack in about a
# minute, for **$0.00**: no CloudHSM instance is ever created.
#
# It builds a throwaway Root CA locally (openssl), has the *real* deployed KMS
# Intermediate key sign a CSR, publishes that two-certificate chain to the stack's
# SSM parameters, emits a synthetic CAChainPublished event, and asserts the trust
# anchor turned on with the chain and a KMS-signed CRL.
#
#   ./scripts/verify_live_control_plane.sh examples/complete
#   ./scripts/verify_live_control_plane.sh examples/complete --restore-pending
#
# --restore-pending puts PENDING-CEREMONY back and disables the trust anchor, so
# the stack is clean for a real ceremony.
#
# This MUTATES the stack: three SSM parameters, one trust anchor, one CRL. Run it
# against a sandbox, and restore afterwards.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TOOL="$REPO_ROOT/modules/hsm-ca/scripts/kms_ca_tool.py"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
TIMEOUT=60
RESTORE=0
STACK_DIR=""

usage() {
  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '[verify] %s\n' "$*" >&2; }
fail() { printf '[verify] FAIL: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --restore-pending) RESTORE=1 ;;
    --timeout) TIMEOUT="${2:?--timeout needs a number}"; shift ;;
    --region) REGION="${2:?--region needs a value}"; shift ;;
    -h|--help) usage 0 ;;
    -*) usage 1 ;;
    *) STACK_DIR="$1" ;;
  esac
  shift
done

[ -n "$STACK_DIR" ] || usage 1
[ -d "$STACK_DIR" ] || fail "no such directory: $STACK_DIR"
command -v terraform >/dev/null || fail "terraform is required"
command -v aws >/dev/null || fail "the AWS CLI is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v openssl >/dev/null || fail "openssl is required"
[ -f "$TOOL" ] || fail "missing $TOOL"

# --------------------------------------------------------------------------- #
# stack outputs
# --------------------------------------------------------------------------- #
log "reading outputs from $STACK_DIR"
outputs="$(terraform -chdir="$STACK_DIR" output -json)" || fail "terraform output failed (is the stack applied?)"

read -r CA_NAME CA_BUNDLE_PARAM ROOT_PARAM INTER_PARAM KMS_ARN TRUST_ANCHOR_ID EVENT_BUS EVENT_SOURCE DETAIL_TYPE ARTIFACT_BUCKET <<EOF
$(python3 - "$outputs" <<'PY'
import json, sys

out = json.loads(sys.argv[1])

def value(name, default=None):
    entry = out.get(name)
    return default if entry is None else entry.get("value", default)

contract = value("ca_contract") or {}
print(
    contract.get("name", "-"),
    contract.get("ca_bundle_ssm_param", "-"),
    contract.get("root_ca_ssm_param", "-"),
    contract.get("intermediate_ca_ssm_param", "-"),
    value("intermediate_kms_key_arn", contract.get("intermediate_kms_key_arn", "-")),
    value("trust_anchor_id", "-") or "-",
    contract.get("event_bus_name", "default"),
    contract.get("event_source", "cloudhsmca.pki"),
    contract.get("event_detail_type", "CAChainPublished"),
    contract.get("artifacts_bucket", "-"),
)
PY
)
EOF

[ "$CA_NAME" != "-" ] || fail "the stack has no ca_contract output"
[ "$TRUST_ANCHOR_ID" != "-" ] || fail "no trust anchor: apply with enable_roles_anywhere = true"
if [ -z "$REGION" ]; then
  REGION="$(python3 -c 'import json,sys; print((json.loads(sys.argv[1]).get("ca_contract") or {}).get("value",{}).get("region","us-east-1"))' "$outputs")"
fi

log "CA=$CA_NAME  region=$REGION  trust anchor=$TRUST_ANCHOR_ID"
log "KMS Intermediate: $KMS_ARN"

WORK="$(mktemp -d)"
cleanup() {
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    log "kept $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# 1. the placeholder trust anchor exists and is DISABLED
# --------------------------------------------------------------------------- #
step1() {
  log "1/5 trust anchor state"
  local anchor
  anchor="$(aws rolesanywhere get-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
    --region "$REGION" --output json)" || fail "get-trust-anchor failed"
  python3 - "$anchor" <<'PY'
import json, sys
a = json.load(sys.stdin)["trustAnchor"]
enabled = a.get("enabled")
src = json.dumps(a.get("source", {}))
print("[verify]   enabled=%s certificates=%d" % (enabled, src.count("BEGIN CERTIFICATE")))
if enabled is not False:
    sys.exit("[verify] FAIL: expected the placeholder anchor to be DISABLED before activation"
             " (it was %r). Re-run with --restore-pending, or apply a fresh stack." % enabled)
PY
}

# --------------------------------------------------------------------------- #
# 2. build a two-certificate chain: local Root, real KMS Intermediate
# --------------------------------------------------------------------------- #
step2() {
  log "2/5 building a chain with the deployed KMS key ($WORK)"
  cat >"$WORK/smoke.cnf" <<'CNF'
[intermediate_dn]
C = US
ST = Washington
L = Seattle
O = cloudhsmca smoke
OU = Live Control Plane Verification
CN = cloudhsmca smoke Intermediate CA

[intermediate_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
CNF

  openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/root.key" 2>/dev/null
  openssl req -new -x509 -key "$WORK/root.key" -sha384 -days 3650 \
    -subj "/C=US/ST=Washington/L=Seattle/O=cloudhsmca smoke/OU=Live Control Plane Verification/CN=cloudhsmca smoke Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$WORK/root_ca.pem" 2>/dev/null || fail "could not create the local Root CA"

  python3 "$TOOL" create-intermediate-csr --signer kms --region "$REGION" \
    --kms-key-id "$KMS_ARN" --cnf "$WORK/smoke.cnf" \
    --dn-section intermediate_dn --extensions intermediate_ext \
    --out "$WORK/intermediate.csr" >/dev/null 2>&1 \
    || fail "create-intermediate-csr failed — the key policy may not allow this caller to GetPublicKey"

  python3 "$TOOL" sign-csr --signer local --local-key "$WORK/root.key" \
    --issuer-cert "$WORK/root_ca.pem" --csr "$WORK/intermediate.csr" \
    --cnf "$WORK/smoke.cnf" --extensions intermediate_ext --days 1825 \
    --out "$WORK/intermediate_ca.pem" >/dev/null 2>&1 \
    || fail "sign-csr failed"

  openssl verify -CAfile "$WORK/root_ca.pem" "$WORK/intermediate_ca.pem" >/dev/null \
    || fail "the synthetic chain does not verify"
  cat "$WORK/root_ca.pem" "$WORK/intermediate_ca.pem" >"$WORK/ca_bundle.pem"
  log "   chain verifies: $(grep -c 'BEGIN CERTIFICATE' "$WORK/ca_bundle.pem") certificates"
}

# --------------------------------------------------------------------------- #
# 3. publish the chain where the ceremony would
# --------------------------------------------------------------------------- #
step3() {
  log "3/5 publishing the chain to SSM ($ROOT_PARAM, $INTER_PARAM, $CA_BUNDLE_PARAM)"
  put_param() {
    aws ssm put-parameter --name "$1" --type String --overwrite \
      --value "file://$2" --region "$REGION" >/dev/null \
      || fail "put-parameter $1 failed"
  }
  put_param "$ROOT_PARAM" "$WORK/root_ca.pem"
  put_param "$INTER_PARAM" "$WORK/intermediate_ca.pem"
  put_param "$CA_BUNDLE_PARAM" "$WORK/ca_bundle.pem"
}

# --------------------------------------------------------------------------- #
# 4. emit the event the ceremony emits
# --------------------------------------------------------------------------- #
step4() {
  log "4/5 emitting $EVENT_SOURCE/$DETAIL_TYPE on bus $EVENT_BUS"
  local detail
  detail="$(python3 - "$CA_NAME" "$CA_BUNDLE_PARAM" "$ROOT_PARAM" "$INTER_PARAM" "$KMS_ARN" "$ARTIFACT_BUCKET" <<'PY'
import json, sys
name, bundle, root, inter, key, bucket = sys.argv[1:7]
print(json.dumps({
    "ca_name": name,
    "cluster_id": "live-verification",
    "intermediate_kms_key_arn": key,
    "ca_bundle_ssm_param": bundle,
    "root_ca_ssm_param": root,
    "intermediate_ca_ssm_param": inter,
    "artifacts_bucket": bucket,
}))
PY
)"
  local entries
  entries="$(python3 - "$EVENT_BUS" "$EVENT_SOURCE" "$DETAIL_TYPE" "$detail" <<'PY'
import json, sys
bus, source, detail_type, detail = sys.argv[1:5]
print(json.dumps({"Entries": [{
    "EventBusName": bus,
    "Source": source,
    "DetailType": detail_type,
    "Detail": detail,
}]}))
PY
)"
  local response
  response="$(aws events put-events --region "$REGION" --entries "$entries" --output json)" \
    || fail "put-events failed"
  python3 - "$response" <<'PY'
import json, sys
r = json.load(sys.stdin)
if r.get("FailedEntryCount"):
    sys.exit("[verify] FAIL: EventBridge dropped the event: %s" % json.dumps(r.get("Entries")))
print("[verify]   event accepted")
PY
}

# --------------------------------------------------------------------------- #
# 5. the consumer must activate the anchor and import a CRL
# --------------------------------------------------------------------------- #
step5() {
  log "5/5 waiting up to ${TIMEOUT}s for activation and CRL import"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  local anchor_id="$TRUST_ANCHOR_ID"

  while :; do
    local anchor crls state
    anchor="$(aws rolesanywhere get-trust-anchor --trust-anchor-id "$anchor_id" \
      --region "$REGION" --output json 2>/dev/null || echo '{}')"
    crls="$(aws rolesanywhere list-crls --trust-anchor-id "$anchor_id" \
      --region "$REGION" --output json 2>/dev/null || echo '{}')"

    state="$(python3 - "$anchor" "$crls" <<'PY'
import json, sys
a = json.loads(sys.argv[1])
c = json.loads(sys.argv[2])
anchor = a.get("trustAnchor", {})
certs = json.dumps(anchor.get("source", {})).count("BEGIN CERTIFICATE")
crls = [x for x in c.get("crls", []) if x.get("enabled")]
print("%s %d %d" % (bool(anchor.get("enabled")), certs, len(crls)))
PY
)"
    set -- $state
    local enabled="$1" certs="$2" ncrls="$3"
    log "   enabled=$enabled certificates=$certs enabled-crls=$ncrls"

    if [ "$enabled" = "True" ] && [ "$certs" -ge 2 ] && [ "$ncrls" -ge 1 ]; then
      log "PASS: the trust anchor holds the published chain and an enabled CRL"
      log "      this proves CreateTrustAnchor accepted the placeholder, EventBridge"
      log "      delivered the event, the key policy let the consumer role sign, and"
      log "      Roles Anywhere accepted the CRL."
      return 0
    fi

    if [ "$(date +%s)" -ge "$deadline" ]; then
      log "timed out with enabled=$enabled certificates=$certs crls=$ncrls"
      log "check: aws logs tail /aws/lambda/${CA_NAME}-crl-issuer --region $REGION --follow"
      return 1
    fi
    sleep 5
  done
}

restore() {
  log "restoring the stack: PENDING-CEREMONY and a disabled trust anchor"
  for param in "$ROOT_PARAM" "$INTER_PARAM" "$CA_BUNDLE_PARAM"; do
    aws ssm put-parameter --name "$param" --type String --overwrite \
      --value PENDING-CEREMONY --region "$REGION" >/dev/null \
      || log "WARNING: could not reset $param"
  done
  aws rolesanywhere disable-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
    --region "$REGION" >/dev/null || log "WARNING: could not disable the trust anchor"
  log "restored"
}

if [ "$RESTORE" = "1" ]; then
  restore
  exit 0
fi

step1
step2
step3
step4
step5
log "done. Run with --restore-pending to reset the stack for a real ceremony."
