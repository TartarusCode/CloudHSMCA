# ceremony/ — the Root CA ceremony as a workflow

The runtime module (`terraform-aws-rolesanywhere-hsm-ca`) is a CA *consumer*: it
reads a certificate chain and provisions IAM Roles Anywhere. This stack is the
CA *producer*: a Step Functions state machine that borrows an HSM for the length
of one ceremony, publishes the chain, and gives the HSM back.

Keeping the ceremony out of Terraform state is the point. An HSM and a signing
host declared in Terraform would have to be created and destroyed across two
applies of one configuration: every reference to them would need a `count` guard
and an index guard, an interrupted run would leave the HSM billing until someone
noticed, and the consumer could not apply until a human had flipped that state.
Here nothing about the ceremony is in Terraform state, so nothing can drift, and
the runtime module applies once.

| | here |
|---|---|
| `aws_cloudhsm_v2_hsm` | Step Functions (`cloudhsmv2:CreateHsm/DeleteHsm`) |
| the signing host | Step Functions (`ec2:RunInstances/TerminateInstances`) |
| a failed ceremony | `Catch` deletes the HSM and terminates the host |
| how many `terraform apply`s | one for this stack, one for the runtime — never to progress a phase |
| audit trail | execution history + CloudWatch, with the ceremony transcript |
| approval gate | an execution input, optionally `waitForTaskToken` |

## What each side owns

Terraform (durable, this stack): the cluster shell, the artifact bucket, the
**KMS Intermediate CA key**, the SSM hand-over parameters, IAM, the log group,
and the state machine.
Terraform (durable, runtime module): the trust anchor, profiles, workload roles,
the CRL, and the backup deny-list — one apply, reading the chain from SSM.
Step Functions (ephemeral, exclusive): the HSM, the ceremony host, and the two
scripts they run.

Creating the Intermediate key here is what makes the foundation a single stack:
the workflow needs `GetPublicKey`/`Sign` to build the Intermediate CSR, and the
runtime module needs `Sign` for CRLs and leaf issuance. The key policy matches
both roles by `aws:PrincipalArn` under the account-root principal, naming the
runtime module's role deterministically (`<name>-crl-issuer`), so neither stack
has to be applied before the other and KMS never has to resolve a role that does
not exist yet. Each signer also carries its own identity-policy grant, under the
same `kms:MessageType=DIGEST` + single-algorithm conditions. Extra principals (an
issuance pipeline) go in `additional_signer_principal_arns`.

## Runbook

```bash
# once
cd ceremony
terraform init
terraform apply \
  -var vpc_id=vpc-… \
  -var 'private_subnet_ids=["subnet-…"]' \
  -var availability_zone=us-west-2a

# bootstrap: creates the Root key, self-signs the Root CA, signs the Intermediate
eval "$(terraform output -raw start_bootstrap_command)"
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED

# then the runtime stack, once, with the chain now present in SSM
cd ../terraform-aws-rolesanywhere-hsm-ca
terraform apply -var intermediate_kms_key_arn="$(terraform -chdir=../ceremony output -raw intermediate_kms_key_arn)"

# five years later: new Intermediate from the same Root
cd ../ceremony && eval "$(terraform output -raw start_rotation_command)"
```

The finished end-to-end walkthrough is `examples/complete` → run the execution →
`examples/runtime`.

## The three sharp edges, and where they live

**Cleanup that preserves the cause.** Every `Task` carries
`Catch: [{ErrorEquals: ["States.ALL"], ResultPath: "$.error", Next: "CleanupHsmOnFailure"}]`.
`CleanupHsmOnFailure` → `DeleteHsmOnFailure` → `CleanupHostOnFailure` →
`TerminateHostOnFailure` → `FailOriginalCause`, which re-raises the *original*
`$.error.Error` / `$.error.Cause`. Cleanup failures are captured into
`$.cleanupHsmError` / `$.cleanupHostError`, never over `$.error`, and each
cleanup task retries three times with backoff before giving up. Success-path
failures (delete, backup, terminate) have their own `Fail` states with the
cause that actually happened.

**SSM agent readiness.** `LaunchCeremonyHost` → `DescribeSsmInstance` →
`IsSsmOnline` gates on `InstanceInformationList[0].PingStatus == "Online"`, with
`GuardSsmPolls` / `WaitForSsm` (15 s, 60 attempts) between polls. `sendCommand`
is only reachable through that gate, so `InvalidInstanceId` cannot happen.

**Bootstrap vs rotation, and the backup proof.** An execution input
`{"mode":"BOOTSTRAP"|"ROTATE_INTERMEDIATE"}` wins; with no input the mode is
inferred from `Clusters[0].State == "UNINITIALIZED"`. Rotation calls
`CreateHsm` with `BackupId` of the newest **READY** backup and refuses to start
without one (`FailNoReadyBackup`), so a rotation can never produce an empty HSM
with no Root key. On the way out the workflow deletes the HSM, polls
`describeClusters` until no HSM remains, then polls `describeBackups` until a
READY backup exists — and only then terminates the host and succeeds.

## One correction to the brief

The cluster states are not `UNINITIALIZED` → `INITIALIZED` at the boundary
between bootstrap and rotation:

- `UNINITIALIZED` — created, never had an HSM. Bootstrap.
- `INITIALIZED` — an HSM exists but the cluster has not been activated yet.
  This is a *transient* state inside bootstrap, not the steady state after it.
- `ACTIVE` — activated and usable.
- `DEGRADED` — initialized once, currently no HSMs. **This is what a cluster
  looks like between ceremonies**, and it is what rotation actually starts from.

Branching on `INITIALIZED` would therefore run bootstrap against a cluster whose
Root key already exists. The workflow keys on `UNINITIALIZED` for bootstrap and
treats everything else as rotation, gated by the READY backup.

Related: activation is not an `InitializeCluster` API task in the ASL. The
API call needs a cluster certificate signed by a customer CA, which only the
ceremony host can produce; SDK 5 performs the same step from the host with
`cloudhsm-cli cluster activate`. That is why the bootstrap branch runs the
runtime module's own ceremony script rather than duplicating its steps — one
implementation, whether it is driven by Terraform or by Step Functions.

## Verified offline, and what is not

`tests/run-all.sh` runs three harnesses. `tests/asl_invariants.py` renders the
definition with the same `templatefile` call Terraform makes and walks it as a
graph (58 states, 16 tasks): every Task catches `States.ALL`, cleanup reaches both
`deleteHsm` and `terminateInstances` and ends in a `Fail` that reads `$.error`, no
cleanup task writes `$.error`, `describeInstanceInformation` precedes both
`sendCommand` states, a bootstrap `CreateHsm` carries no `BackupId` while a
rotation one does, an explicit mode is honoured and an unknown one refused, and a
READY backup gates both the restore and the completion.

`tests/crypto` drives `kms_ca_tool.py` through the whole chain with local
signers and verifies every artifact with `openssl`; `tests/ceremony` renders
`hsm_ceremony.sh.tftpl` — the script the workflow runs — and executes it against a
stub `cloudhsm-cli` that really signs. Both script templates are also `bash -n`'d
as part of the ASL harness. `terraform validate` covers the stack itself.

Not verified here: the live control plane. Nothing in this environment can create
a CloudHSM cluster, so the API shapes and timings (HSM ACTIVE, deletion, backup
completion) are assumptions checked against the API reference, not observed. The
first real bootstrap is the test for them, and the failure paths are designed to
fail loudly and clean up rather than leave an HSM billing.
