# Tests

Seven offline harnesses across the three modules. None needs an AWS account, an
HSM, or credentials.

```bash
make test        # or: tests/run-all.sh
```

| harness | module under test |
|---|---|
| `tests/module/smoke.sh` | `modules/hsm-ca` |
| `tests/asl_invariants.py` | `modules/hsm-ca` |
| `tests/crypto/test_kms_ca_tool.sh` | `modules/hsm-ca` |
| `tests/ceremony/run.sh` | `modules/hsm-ca` |
| `tests/lambda/test_lambda.py` | `modules/roles-anywhere` |
| `modules/alb-mtls/tests/module/smoke.sh` | `modules/alb-mtls` |
| `modules/alb-mtls/tests/lambda/test_lambda.py` | `modules/alb-mtls` |

## `module/smoke.sh`

Evaluates the engine's variable-only locals the way `terraform plan` does, for
both `auto_bootstrap` paths, asserts `Module = "cloudhsmca"` wins over a
caller-supplied tag, that `allowed_kms_signer_role_arns = null` (the `<name>-*`
default) and that an explicit list replaces it, and checks three variable
validations — all in **one** console invocation for the rejections, because
console reports every invalid variable an expression references and each extra
process costs ~7 s of provider startup.

`terraform validate` never evaluates locals, so a local that raises only when it
is computed passes every gate and fails at the first plan. This harness was
written for exactly that: `fileexists("")` raising *"'.' is a directory, not a
file"* on Terraform 1.9.x.

Locals that read a resource attribute or a data source (the state machine
definition reads the AMI, the bucket and the event bus) cannot be evaluated
offline; `terraform plan` is the only test for those.

## `asl_invariants.py`

Renders `modules/hsm-ca/statemachine.asl.json.tftpl` with the same `templatefile`
call Terraform makes and walks the result as a graph:

| check | why it matters |
|---|---|
| every Task catches `States.ALL` | a botched ceremony must not leave the HSM billing |
| cleanup reaches `deleteHsm` **and** `terminateInstances` | both halves of the teardown |
| every Catch path ends in a `Fail`, and the original cause survives | the reported error is the real one |
| no JSONPath hides inside a list; every EC2/SSM call uses `States.Array(...)` | `"InstanceIds": ["$.host…"]` sends that text, not the id |
| `describeInstanceInformation` precedes both `sendCommand` states, gated on `PingStatus == Online` | EC2 `running` is not SSM `Online` |
| one `CreateHsm` with `BackupId`, one without | rotation restores; bootstrap does not |
| a READY backup gates the completion | the Root key must be escrowed |
| the definition ends with `PublishCaReadyEvent` (`eventbridge:putEvents`) | consumers activate from the event, not from Terraform |
| that event carries `source`, `detail-type`, the bus and the full detail object | a consumer matches on them |
| **no `rolesanywhere` string anywhere** | the engine must stay workload-agnostic |
| the publish happens after the host is terminated and before `Succeed` | nothing becomes activatable before teardown and escrow |

It also renders both script templates and runs `bash -n` on them.

## `crypto/test_kms_ca_tool.sh`

Drives `modules/hsm-ca/scripts/kms_ca_tool.py` through the full chain with a
local key standing in for KMS and for the HSM (`--signer local`), then hands every
artifact to `openssl`: `spki-from-point` byte-identical to `openssl pkey -pubout
-outform DER`, root self-signature, CSR signature, the Intermediate issued by the
root, the clientAuth leaf, a DER CRL that `openssl crl -verify` accepts, and the
two refusal paths (tampered CSR, undefined extension).

## `ceremony/run.sh`

Renders `modules/hsm-ca/scripts/hsm_ceremony.sh.tftpl` — the script the workflow
runs on the ephemeral host — with `terraform console`, syntax-checks it, then
executes it end to end against stubs for `cloudhsm-cli`, the AWS CLI, `dnf`,
`curl`, `systemctl` and `uv`. The `cloudhsm-cli` stub really signs and returns
base64 `r||s`, exactly as Client SDK 5 does, so the tool's DER conversion is
exercised. Everything else is real: `jq`, `openssl`, the CA tool, both OpenSSL
profiles. The run must reach `COMPLETE` and the resulting chain must verify
outside the script.

## `lambda/test_lambda.py`

Extracts the handler **from the heredoc in
`modules/roles-anywhere/crl_issuer_lambda.tf`** — the bytes that get zipped, not a
copy — and runs it against a boto3 stand-in backed by a real P-384 key. Four
paths:

| path | asserted |
|---|---|
| `CAChainPublished` envelope | `UpdateTrustAnchor` gets `CERTIFICATE_BUNDLE` with both certificates, `EnableTrustAnchor` is called, then a CRL is imported; `activated: true` |
| scheduled tick, no chain yet | returns `{"skipped": "chain-not-published"}`, imports nothing |
| scheduled tick, chain published | imports a CRL, `activated: false`, and never touches the trust anchor |
| `CAChainPublished` with no chain | raises — an event without a chain is a bug, not a no-op |

Then the CRL itself: `openssl crl -verify` accepts it, the AKI equals the
issuer's SKI, both revoked serials survive, the blob handed to `import_crl` is
**PEM** (the API rejects raw DER), `GetCrl` returns the same SHA-256, and an
empty-revocation CRL is still valid.

## What none of this covers

The live control plane: CloudHSM cluster activation timing, `configure-cli`
against a real hsm2m.medium ENI, KMS's enforcement of the key-policy conditions
(the `aws:PrincipalArn` match against the consumer role), `CreateTrustAnchor`
accepting the disabled placeholder, `UpdateTrustAnchor`/`EnableTrustAnchor`
behaviour, Roles Anywhere's acceptance of the CRL, and EventBridge actually
delivering the event to the consumer's rule. The first real bootstrap is the test
for those; the failure paths are built to fail loudly and tear down rather than
leave an HSM billing.

## Live Sandbox Verification ($0 No-HSM Smoke Test)

Three of the four live-only unknowns can be proved without a CloudHSM instance:

```bash
# after terraform apply with auto_bootstrap = false and enable_roles_anywhere = true
./scripts/verify_live_control_plane.sh examples/complete
./scripts/verify_live_control_plane.sh examples/complete --restore-pending
```

What it does, in about a minute, for **$0.00**:

1. asserts the placeholder trust anchor exists and is `DISABLED`;
2. builds a two-certificate chain locally — an ephemeral openssl Root CA plus an
   Intermediate signed by the **real deployed KMS key** (`kms_ca_tool.py
   create-intermediate-csr` + `sign-csr`), verified with `openssl verify`;
3. writes it to the stack's `root_ca.pem`, `intermediate_ca.pem` and
   `ca_bundle.pem` SSM parameters, where the ceremony would write it;
4. emits a synthetic `cloudhsmca.pki` / `CAChainPublished` with
   `aws events put-events` and fails if EventBridge reports `FailedEntryCount`;
5. polls `get-trust-anchor` and `list-crls` for up to 60 s and asserts the anchor
   is `ENABLED` with two certificates **and** an enabled CRL.

That single run exercises `CreateTrustAnchor`'s placeholder acceptance, the
EventBridge rule and its delivery, the consumer Lambda, the KMS key policy's
`CaSignDigestOnly` delegation (the Lambda signs the CRL with the real key), and
Roles Anywhere accepting `ImportCrl`.

Before mutating anything the script writes `<stack-dir>/.verify-live-snapshot.json`
(SSM values, anchor state, revocation object, account and CA name).
`--restore-pending --confirm-sandbox` restores only that snapshot, refuses a
snapshot from another account or CA, reads every write back, and exits nonzero on
a partial restore. The script mutates a deployed stack: use a sandbox.

The fourth unknown — CloudHSM control-plane timing (cluster activation, HSM
`ACTIVE`, the ENI `configure-cli` step) — still needs one real ceremony, and costs
about $1.50/hour while it runs.
