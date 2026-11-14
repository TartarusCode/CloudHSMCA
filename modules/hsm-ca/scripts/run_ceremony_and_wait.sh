#!/bin/bash
# =============================================================================
# run_ceremony_and_wait.sh — the auto_bootstrap waiter
#
# Called from terraform_data.auto_bootstrap's local-exec (var.auto_bootstrap =
# true). Starts the bootstrap ceremony and blocks until the execution ends, so a
# failed ceremony fails `terraform apply` with the execution's own cause instead
# of leaving a DISABLED trust anchor and no obvious reason.
#
# Idempotent: if the chain is already published, there is nothing to do, so a
# re-apply (or a retry after a partial run) does not spend another HSM hour.
#
# Environment (set by the module):
#   STATE_MACHINE_ARN  the ceremony state machine
#   SSM_CA_BUNDLE      /<name>/pki/ca_bundle.pem
#   PKI_NAME           var.name, for execution naming
#   AWS_REGION         region of the stack
#   WAIT_TIMEOUT       seconds to keep polling (default 3600)
# =============================================================================
set -euo pipefail

STATE_MACHINE_ARN="${STATE_MACHINE_ARN:?STATE_MACHINE_ARN is required}"
SSM_CA_BUNDLE="${SSM_CA_BUNDLE:?SSM_CA_BUNDLE is required}"
PKI_NAME="${PKI_NAME:-pki}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-3600}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"

command -v aws >/dev/null 2>&1 || {
  echo "auto_bootstrap needs the AWS CLI on the machine running terraform apply" >&2
  exit 1
}

log() { printf '[auto_bootstrap] %s\n' "$*" >&2; }

# --- idempotency guard -------------------------------------------------------
# A published chain means a ceremony already succeeded (or is running right now
# and wrote it): either way, starting another HSM is wrong.
if bundle=$(aws ssm get-parameter --name "$SSM_CA_BUNDLE" \
      --with-decryption --region "$AWS_REGION" \
      --query 'Parameter.Value' --output text 2>/dev/null); then
  certs=$(grep -c -- '-----BEGIN CERTIFICATE-----' <<<"$bundle" || true)
  if [ "${certs:-0}" -ge 2 ] && ! grep -q 'PENDING-CEREMONY' <<<"$bundle"; then
    log "chain already published at $SSM_CA_BUNDLE ($certs certificates): nothing to do"
    exit 0
  fi
  log "bundle present but not a usable chain ($certs certificates): starting the ceremony"
else
  log "no bundle at $SSM_CA_BUNDLE yet: starting the ceremony"
fi

# --- start ------------------------------------------------------------------
execution_name="bootstrap-${PKI_NAME}-$(date -u +%Y%m%dT%H%M%SZ)"
log "starting $execution_name"

if ! execution_arn=$(aws stepfunctions start-execution \
      --state-machine-arn "$STATE_MACHINE_ARN" \
      --name "$execution_name" \
      --input '{"mode":"BOOTSTRAP"}' \
      --region "$AWS_REGION" \
      --query 'executionArn' --output text); then
  log "start-execution failed"
  exit 1
fi
log "execution: $execution_arn"

# --- poll -------------------------------------------------------------------
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))

while :; do
  read -r status error cause < <(aws stepfunctions describe-execution \
    --execution-arn "$execution_arn" \
    --region "$AWS_REGION" \
    --query '[status, error, cause]' --output text)

  case "$status" in
    SUCCEEDED)
      log "ceremony SUCCEEDED: the trust anchor is enabled and a CRL is imported"
      exit 0
      ;;
    FAILED|TIMED_OUT|ABORTED)
      log "ceremony $status"
      log "  error: ${error:-<none>}"
      log "  cause: ${cause:-<none>}"
      log "the HSM and the ceremony host are torn down by the workflow's cleanup path;"
      log "fix the cause above and re-apply (the guard skips a completed ceremony)"
      exit 1
      ;;
    RUNNING|PENDING_REDRIVE)
      ;;
    *)
      log "unexpected execution status: $status"
      exit 1
      ;;
  esac

  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "gave up after ${WAIT_TIMEOUT}s with the execution still $status"
    log "it continues in AWS: $execution_arn"
    exit 1
  fi
  sleep "$POLL_INTERVAL"
done
