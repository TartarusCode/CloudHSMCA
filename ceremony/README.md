# ceremony/ — the Root CA ceremony as a workflow

The runtime module (`terraform-aws-rolesanywhere-hsm-ca`) is a CA *consumer*: it
reads a certificate chain and provisions IAM Roles Anywhere. This stack is the
CA *producer*: a Step Functions state machine that borrows an HSM for the length
of one ceremony, publishes the chain, and gives the HSM back.

That split is the whole point. A boolean `ceremony_mode` inside the module made
Terraform act as a temporal state machine: `count = var.ceremony_mode ? 1 : 0`
on the HSM and the signing host, `[0]` index guards wherever a phase-2 local
touched them, and a two-apply dance whose second apply deleted what the first
created. Here nothing about the ceremony is in Terraform state, so nothing can
drift, and the runtime module applies once.

| | runtime module (`ceremony_mode`) | this stack |
|---|---|---|
| who owns `aws_cloudhsm_v2_hsm` | Terraform | Step Functions (`cloudhsmv2:CreateHsm/DeleteHsm`) |
| who owns the signing host | Terraform | Step Functions (`ec2:RunInstances/TerminateInstances`) |
| failed ceremony | HSM keeps billing until a human notices | `Catch` deletes it and terminates the host |
| how many `terraform apply`s | two | one, ever |
| audit trail | apply history | execution history + CloudWatch, with the ceremony transcript |
| approval gate | a human flips a variable | input, and optionally `waitForTaskToken` |

## What each side owns

Terraform (durable, this stack): the cluster shell, the artifact bucket, the SSM
hand-over parameters, IAM, the log group, and the state machine.
Terraform (durable, runtime module): the KMS Intermediate key, the Roles Anywhere
trust anchor, profiles, workload roles, and the CRL.
Step Functions (ephemeral, exclusive): the HSM, the ceremony host, and the two
scripts they run.

## Runbook

```bash
# once
cd ceremony
terraform init
terraform apply \
  -var vpc_id=vpc-… \
  -var 'private_subnet_ids=["subnet-…"]' \
  -var availability_zone=us-west-2a \
  -var intermediate_kms_key_arn="$(terraform -chdir=../terraform-aws-rolesanywhere-hsm-ca output -raw intermediate_kms_key_arn)"

# bootstrap: creates the Root key, self-signs the Root CA, signs the Intermediate
eval "$(terraform output -raw start_bootstrap_command)"
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED

# then the runtime stack, once, with the chain now present in SSM
cd ../terraform-aws-rolesanywhere-hsm-ca && terraform apply

# five years later: new Intermediate from the same Root
cd ../ceremony && eval "$(terraform output -raw start_rotation_command)"
```

The ceremony host role must be allowed to sign with the Intermediate key: add
`ceremony_host_role_arn` to the runtime module's
`intermediate_signer_principal_arns`. The alternative — an `aws_kms_grant` from
this stack — cannot express the `kms:MessageType=DIGEST` condition, so the key
policy stays the single place that hardens it.

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

`tests/asl_invariants.py` renders the definition with the same `templatefile`
call Terraform makes, then walks it as a graph: 58 states, 16 tasks. It asserts
every Task catches `States.ALL`, that cleanup reaches both `deleteHsm` and
`terminateInstances` and ends in a `Fail` that reads `$.error`, that no cleanup
task writes `$.error`, that `describeInstanceInformation` precedes both
`sendCommand` states, that a bootstrap `CreateHsm` carries no `BackupId` while a
rotation one does, that an explicit mode is honoured and an unknown one refused,
and that a READY backup gates both the restore and the completion. It also
renders both script templates and runs `bash -n` on them. `terraform validate`
covers the stack itself.

Not verified here: the live control plane. Nothing in this environment can create
a CloudHSM cluster, so the API shapes and timings (HSM ACTIVE, deletion, backup
completion) are assumptions checked against the API reference, not observed. The
first real bootstrap is the test for them, and the failure paths are designed to
fail loudly and clean up rather than leave an HSM billing.
