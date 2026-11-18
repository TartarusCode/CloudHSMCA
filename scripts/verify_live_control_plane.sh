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
#   ./scripts/verify_live_control_plane.sh examples/complete --restore-pending --confirm-sandbox
#
# Before mutating anything the run writes a snapshot to
# <stack-dir>/.verify-live-snapshot.json. --restore-pending refuses to run
# without --confirm-sandbox, refuses a snapshot from another account or CA, and
# restores only those recorded values. Every write is read back; a partial
# restore exits nonzero instead of reporting success.
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
CONFIRM_SANDBOX=0
STACK_DIR=""
SNAPSHOT=""
# Where the Roles Anywhere consumer reads revoked serials from. The module's
# default; override with --revocations-key if the stack changed it.
REVOCATIONS_KEY="revocations/revoked.json"

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log() { printf '[verify] %s\n' "$*" >&2; }
fail() { printf '[verify] FAIL: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --restore-pending) RESTORE=1 ;;
    --confirm-sandbox) CONFIRM_SANDBOX=1 ;;
    --timeout) TIMEOUT="${2:?--timeout needs a number}"; shift ;;
    --region) REGION="${2:?--region needs a value}"; shift ;;
    --revocations-key) REVOCATIONS_KEY="${2:?--revocations-key needs a value}"; shift ;;
    -h|--help) usage 0 ;;
    -*) usage 1 ;;
    *) STACK_DIR="$1" ;;
  esac
  shift
done

[ -n "$STACK_DIR" ] || usage 1
[ -d "$STACK_DIR" ] || fail "no such directory: $STACK_DIR"
SNAPSHOT="$STACK_DIR/.verify-live-snapshot.json"
command -v terraform >/dev/null || fail "terraform is required"
command -v aws >/dev/null || fail "the AWS CLI is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v openssl >/dev/null || fail "openssl is required"
[ -f "$TOOL" ] || fail "missing $TOOL"

# kms_ca_tool.py imports these lazily, so a missing one surfaces as a traceback
# halfway through the run. An `aws login` session additionally needs the `crt`
# extra for botocore, which is not installed by plain boto3.
if ! python3 -c "import boto3, cryptography, awscrt" >/dev/null 2>&1; then
  fail "python3 needs boto3, cryptography and the awscrt extra: \
uv pip install 'boto3[crt]' cryptography"
fi

# --------------------------------------------------------------------------- #
# stack outputs
# --------------------------------------------------------------------------- #
log "reading outputs from $STACK_DIR"
outputs="$(terraform -chdir="$STACK_DIR" output -json)" || fail "terraform output failed (is the stack applied?)"
# With no state, `terraform output -json` succeeds and prints {}. Saying "nothing
# is applied" is more useful than the first missing-output check below, which
# would report a contract field as absent when the whole stack is.
if [ -z "${outputs//[[:space:]]/}" ] || [ "${outputs//[[:space:]]/}" = "{}" ]; then
  fail "nothing is applied in $STACK_DIR — run terraform apply there first"
fi

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
# The script itself arrives on stdin (`python3 - ... <<'PY'`), so the payload
# must come from argv, not sys.stdin.
a = json.loads(sys.argv[1])["trustAnchor"]
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

# A CSR has no issuer yet, so it must not ask for an authority key identifier;
# the certificate profile below adds it at signing time.
[intermediate_csr_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

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

  if ! python3 "$TOOL" create-intermediate-csr --signer kms --region "$REGION" \
      --kms-key-id "$KMS_ARN" --cnf "$WORK/smoke.cnf" \
      --dn-section intermediate_dn --extensions intermediate_csr_ext \
      --out "$WORK/intermediate.csr" >"$WORK/csr.log" 2>&1; then
    sed 's/^/[verify]   /' "$WORK/csr.log" >&2
    fail "create-intermediate-csr failed: the key policy must allow this caller kms:Sign (the CSR is signed by the KMS key) — add it to allowed_kms_signer_role_arns"
  fi

  if ! python3 "$TOOL" sign-csr --signer local --local-key "$WORK/root.key" \
      --issuer-cert "$WORK/root_ca.pem" --csr "$WORK/intermediate.csr" \
      --cnf "$WORK/smoke.cnf" --extensions intermediate_ext --days 1825 \
      --out "$WORK/intermediate_ca.pem" >"$WORK/sign.log" 2>&1; then
    sed 's/^/[verify]   /' "$WORK/sign.log" >&2
    fail "sign-csr failed"
  fi

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
# 3b. seed one revoked serial
#
# Roles Anywhere rejects a CRL that revokes nothing ("At least one of the
# included CRLs doesn't include a revoked certificate"), so the import half of
# this check needs a non-empty revocation list. Serial 1 stands in for a real
# revocation; --restore-pending puts the empty list back.
# --------------------------------------------------------------------------- #
seed_revocation() {
  log "3b/5 seeding one revoked serial in s3://$ARTIFACT_BUCKET/$REVOCATIONS_KEY"
  # The reason is an RFC 5280 code name, not free text: the issuer maps it and
# rejects anything else with "unknown revocation reason".
  printf '{"revoked":[{"serial":"0x01","reason":"key_compromise"}]}\n' >"$WORK/revoked.json"
  aws s3 cp --region "$REGION" "$WORK/revoked.json" \
    "s3://$ARTIFACT_BUCKET/$REVOCATIONS_KEY" >/dev/null \
    || fail "could not write the revocation list to s3://$ARTIFACT_BUCKET/$REVOCATIONS_KEY"
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
# --entries takes the array itself, not an {"Entries": ...} envelope.
print(json.dumps([{
    "EventBusName": bus,
    "Source": source,
    "DetailType": detail_type,
    "Detail": detail,
}]))
PY
)"
  local response
  response="$(aws events put-events --region "$REGION" --entries "$entries" --output json)" \
    || fail "put-events failed"
  python3 - "$response" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
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
      --region "$REGION" --output json 2>&1)" \
      || { log "get-trust-anchor failed: $anchor"; return 1; }
    # list-crls takes no trust-anchor argument: it returns every CRL in the
    # account and Region, so the anchor is matched on the ARN below. Swallowing
    # a usage error here once made this loop report zero CRLs forever.
    crls="$(aws rolesanywhere list-crls --region "$REGION" --output json 2>&1)" \
      || { log "list-crls failed: $crls"; return 1; }

    state="$(python3 - "$anchor" "$crls" <<'PY'
import json, sys
a = json.loads(sys.argv[1])
c = json.loads(sys.argv[2])
anchor = a.get("trustAnchor", {})
arn = anchor.get("trustAnchorArn", "")
certs = json.dumps(anchor.get("source", {})).count("BEGIN CERTIFICATE")
crls = [x for x in c.get("crls", [])
        if x.get("enabled") and x.get("trustAnchorArn") == arn]
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

###############################################################################
# Snapshot before any mutation, restore only from that snapshot
###############################################################################

write_snapshot() {
  local account
  account="$(aws sts get-caller-identity --query Account --output text --region "$REGION")"
  aws rolesanywhere get-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
    --region "$REGION" --output json > "$WORK/anchor-before.json" \
    || fail "could not snapshot the trust anchor"
  for pair in "root:$ROOT_PARAM" "intermediate:$INTER_PARAM" "bundle:$CA_BUNDLE_PARAM"; do
    local name="${pair%%:*}" param="${pair#*:}"
    aws ssm get-parameter --name "$param" --with-decryption \
      --query Parameter.Value --output text --region "$REGION" \
      > "$WORK/$name-before.pem" || fail "could not snapshot $param"
  done
  if aws s3api get-object --bucket "$ARTIFACT_BUCKET" --key "$REVOCATIONS_KEY" \
       "$WORK/revocations-before.json" --region "$REGION" >/dev/null 2>&1; then
    :
  else
    rm -f "$WORK/revocations-before.json"
  fi
  SNAP_ACCOUNT="$account" SNAP_CA_NAME="$CA_NAME" SNAP_WORK="$WORK" \
    python3 - "$SNAPSHOT" <<'PY'
import base64, json, os, sys
work = os.environ["SNAP_WORK"]
snap = {
    "account": os.environ["SNAP_ACCOUNT"],
    "ca_name": os.environ["SNAP_CA_NAME"],
    "root": open(os.path.join(work, "root-before.pem")).read(),
    "intermediate": open(os.path.join(work, "intermediate-before.pem")).read(),
    "bundle": open(os.path.join(work, "bundle-before.pem")).read(),
    "anchor": json.load(open(os.path.join(work, "anchor-before.json")))["trustAnchor"],
}
rev = os.path.join(work, "revocations-before.json")
snap["revocations_b64"] = (
    base64.b64encode(open(rev, "rb").read()).decode("ascii") if os.path.exists(rev) else None)
json.dump(snap, open(sys.argv[1], "w"))
PY
  chmod 600 "$SNAPSHOT"
  log "snapshot written to $SNAPSHOT (account $account, anchor enabled=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["anchor"].get("enabled"))' "$SNAPSHOT"))"
}

restore() {
  [ "$CONFIRM_SANDBOX" = "1" ] \
    || fail "--restore-pending requires --confirm-sandbox: it mutates a live trust anchor"
  [ -n "$SNAPSHOT" ] && [ -f "$SNAPSHOT" ] \
    || fail "no snapshot at $SNAPSHOT: restore is only allowed from a snapshot this script took"

  local account recorded
  account="$(aws sts get-caller-identity --query Account --output text --region "$REGION")"
  recorded="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["account"])' "$SNAPSHOT")"
  [ "$account" = "$recorded" ] \
    || fail "snapshot belongs to account $recorded, current account is $account: refusing to restore"
  local snap_name
  snap_name="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ca_name"])' "$SNAPSHOT")"
  [ "$snap_name" = "$CA_NAME" ] \
    || fail "snapshot belongs to CA $snap_name, current stack is $CA_NAME: refusing to restore"

  python3 - "$SNAPSHOT" "$WORK" <<'PY'
import base64, json, os, sys
snap = json.load(open(sys.argv[1])); work = sys.argv[2]
for name in ("root", "intermediate", "bundle"):
    open(os.path.join(work, "restore-%s.pem" % name), "w").write(snap[name])
if snap.get("revocations_b64") is not None:
    open(os.path.join(work, "restore-revoked.json"), "wb").write(
        base64.b64decode(snap["revocations_b64"]))
open(os.path.join(work, "restore-enabled"), "w").write(
    "1" if snap["anchor"].get("enabled") else "0")
PY

  local rc=0 want value actual
  for pair in "$ROOT_PARAM:root" "$INTER_PARAM:intermediate" "$CA_BUNDLE_PARAM:bundle"; do
    local param="${pair%:*}" name="${pair#*:}"
    if ! aws ssm put-parameter --name "$param" --type String --overwrite \
         --value "file://$WORK/restore-$name.pem" --region "$REGION" >/dev/null; then
      log "ERROR: could not restore $param"; rc=1; continue
    fi
    want="$(cat "$WORK/restore-$name.pem")"
    actual="$(aws ssm get-parameter --name "$param" --with-decryption \
      --query Parameter.Value --output text --region "$REGION" 2>/dev/null || true)"
    [ "$want" = "$actual" ] || { log "ERROR: $param did not read back as restored"; rc=1; }
  done

  if [ "$(cat "$WORK/restore-enabled")" = "1" ]; then
    aws rolesanywhere enable-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
      --region "$REGION" >/dev/null \
      || { log "ERROR: could not re-enable the trust anchor (it was enabled before)"; rc=1; }
  else
    aws rolesanywhere disable-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
      --region "$REGION" >/dev/null \
      || { log "ERROR: could not disable the trust anchor"; rc=1; }
  fi
  actual="$(aws rolesanywhere get-trust-anchor --trust-anchor-id "$TRUST_ANCHOR_ID" \
    --region "$REGION" --query 'trustAnchor.enabled' --output text 2>/dev/null || true)"
  [ "$actual" = "$(python3 -c 'import sys;print("True" if sys.argv[1]=="1" else "False")' "$(cat "$WORK/restore-enabled")")" ] \
    || { log "ERROR: trust anchor enabled state did not read back as restored"; rc=1; }

  if [ -f "$WORK/restore-revoked.json" ]; then
    if aws s3 cp --region "$REGION" "$WORK/restore-revoked.json" \
         "s3://$ARTIFACT_BUCKET/$REVOCATIONS_KEY" >/dev/null 2>&1 \
       && aws s3api get-object --bucket "$ARTIFACT_BUCKET" --key "$REVOCATIONS_KEY" \
            "$WORK/revocations-restored.json" --region "$REGION" >/dev/null 2>&1 \
       && cmp -s "$WORK/restore-revoked.json" "$WORK/revocations-restored.json"; then
      :
    else
      log "ERROR: the revocation list was not restored byte-for-byte"; rc=1
    fi
  fi

  [ "$rc" -eq 0 ] || fail "restore was partial; see the ERROR lines above"
  log "restore verified: snapshot values, anchor state and revocations match"
}

if [ "$RESTORE" = "1" ]; then
  restore
  exit 0
fi

write_snapshot

step1
step2
step3
seed_revocation
step4
step5
log "done. Run with --restore-pending to reset the stack for a real ceremony."
