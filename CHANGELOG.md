# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module follows
semantic versioning once it is tagged.

## [Unreleased]

Security and correctness pass over a full audit. Most items are offline-verified by
the harnesses; the cloud-side acceptance points are called out below.

### Fixed

- **IAM prefix**: the ceremony execution role granted `cloudhsmv2:*`, which is not
  an IAM action namespace; it now grants `cloudhsm:CreateHsm/DeleteHsm/
  DescribeClusters/DescribeBackups/InitializeCluster`. The `aws-sdk:cloudhsmv2:`
  Step Functions integration identifiers are unchanged.
- **First bootstrap could never complete**: a new cluster is `UNINITIALIZED`, but
  nothing signed its CSR or called `InitializeCluster`. The ceremony now claims
  the cluster with a separate commissioning CA (`commissioning_ca`), installs that
  CA as the client trust anchor, and only then activates. The key stays out of
  Terraform state (SSM SecureString or a pre-signed cluster certificate).
- **State machine variables**: poll counters and the resolved mode are workflow
  variables (`$hsmPoll`, `$mode`, …) with `.$` expression assignments; routing and
  failure causes read those variables instead of overwriting payload paths.
- **Backup field and escrow**: gates read `BackupState`, and the escrow check now
  requires a *new* backup relative to a pre-run baseline. The verified backup id
  is committed to SSM before the host is terminated or the chain announced.
- **Failure cleanup**: every post-allocation failure (poll exhaustion, non-success
  SSM status, teardown/backup failure) records `$.error` and re-enters
  stage-appropriate cleanup before re-raising the original cause.
- **SSM eventual consistency**: `getCommandInvocation` retries only
  `SSM.InvocationNotFound`; permanent errors still go through cleanup.
- **Cluster lease**: a conditional, execution-owned DynamoDB lease prevents
  overlapping ceremonies; a lease whose owner is terminal is reclaimed.
- **`jq` boolean**: the root-key extractability check tested `false // "unknown"`,
  which `jq` treats as absent. It now requires the JSON boolean `false`.
- **Supply chain**: the CloudHSM CLI RPM checksum is mandatory and verified before
  any credential read; tooling and OpenSSL profiles are fetched by S3 version id;
  `uv` is version-pinned and its installer checksum is optional but recommended.
- **CRL quota**: Roles Anywhere allows two CRLs per anchor. The handler pages
  `ListCrls`, imports the new CRL before retiring the old generation, and deletes
  owned CRLs (not just disables them).
- **Chain reconciliation**: both consumer Lambdas reconcile the installed chain on
  every invocation, so a missed event or late consumer self-heals on the scheduled
  tick. Read-back verifies the anchor/trust store retained the committed generation.
- **ALB revocation source**: the ALB consumer now reads the same S3 revocation
  object as Roles Anywhere by default; an SSM parameter is an explicit override.
  A configured but missing/blank/invalid source fails closed instead of clearing
  the installed CRL. An explicit `{"revoked": []}` is the only way to clear.
- **Placeholder CA**: the ALB placeholder is a checked-in public certificate; its
  private key is generated outside Terraform and destroyed, so state readers have
  no signing authority over a listener.
- **KMS Intermediate guard**: `prevent_destroy` blocks an accidental replacement
  or destruction of the signing key while the published chain uses it.
- **Rotation-only plans**: `enable_bootstrap = false` renders out the bootstrap
  states instead of indexing `bootstrap_objects[0]`; `auto_bootstrap = true`
  requires `enable_bootstrap = true`.
- **Signer allowlist**: the default is now an empty list (ceremony host only), and
  wildcard ARNs are rejected; the composite stack passes its exact CRL issuer ARN.
- **Session durations**: a profile may request 900–3599 s, while the IAM role
  ceiling is floored at 3600 s (or an explicit `role_max_session_duration`).
- **Live-verification restore**: `--restore-pending` requires `--confirm-sandbox`,
  restores only a snapshot taken by a prior run in the same account and CA, reads
  every write back, and exits nonzero on a partial restore.

Still requires live AWS: `UNINITIALIZED → INITIALIZED → ACTIVE` on a disposable
cluster, KMS key-policy authorization, the CRL quota behavior, and listener
enforcement. The offline harnesses prove ordering and shape, not service acceptance.

## [0.5.1] - 2026-11-15

Everything here came out of the first live sandbox run: an apply in us-west-2 with
both consumers enabled, then `scripts/verify_live_control_plane.sh` against it. The
offline harnesses had all passed; none of these were visible without calling AWS.

### Fixed

- The ceremony state machine could not be created at all: `describeBackups` was
  called with `SortBy`/`SortOrder`, which the API does not have, so
  `aws_sfn_state_machine` failed with `SCHEMA_VALIDATION_FAILED`. Both call sites
  use `SortAscending: false`, which still puts the newest backup at index 0 for
  every `$.backups.Backups[0]` consumer.
- `CreateHsmFromBackup` passed `BackupId` to `cloudhsmv2:createHsm`, which accepts
  only `ClusterId` and `AvailabilityZone`. No parameter is needed for the restore:
  CloudHSM restores the cluster's most recent backup onto the new HSM itself, and
  `RequireReadyBackupRequested` still refuses to create one unless a `READY` backup
  exists.
- The Roles Anywhere CRL Lambda could never import its first CRL. With no
  revocation list in the bucket, `GetObject` returned `AccessDenied` rather than
  `NoSuchKey` (the role has no `s3:ListBucket`), and `ImportCrl` rejects a CRL that
  revokes nothing. The module now seeds `revocations/revoked.json` with
  `{"revoked": []}` (content changes are ignored, so operator edits survive).
- An emptied revocation list no longer leaves a stale CRL active: the handler lists
  the account's CRLs, matches them by `trustAnchorArn`, and disables every enabled
  one before returning `{"skipped": "no-revocations"}`. `rolesanywhere:ListCrls`
  moved to its own `*` statement — it is account-wide and supports no
  resource-level permission.
- `modules/alb-mtls` called `add_trust_store_revocations(Revocations=[{
  RevocationS3Bucket, ... }])`. The parameter is `RevocationContents` and each
  element is an `S3Bucket`/`S3Key`/`S3ObjectVersion` triple. The same policy also
  denied `DescribeTrustStoreRevocations` by pinning it to the trust store ARN;
  `Describe*` supports no resource-level permission, so it is now a separate `*`
  statement and only `ModifyTrustStore` and the revocation add/remove calls are
  scoped to the trust store.
- `scripts/verify_live_control_plane.sh`, four defects: two blocks passed their
  JSON payload in `argv` but read `sys.stdin` (which is the program); `put-events`
  received `{"Entries": [...]}` instead of the array; `list-crls
  --trust-anchor-id` is not a flag that exists, and the `|| echo '{}'` around it
  turned a usage error into "zero CRLs forever"; and the CSR profile carried an
  `authorityKeyIdentifier` that a CSR cannot have. The seed revocation also needed
  a real RFC 5280 reason code.

### Added

- `tests/asl_invariants.py` validates every `aws-sdk:<service>:<action>` parameter
  block against the botocore service model — 16 operations, no exceptions — and
  asserts that every `createHsm` passes only `ClusterId` and `AvailabilityZone`
  with the READY gate ahead of the rotation call.
- Both Lambda harnesses validate their stub keyword arguments against the same
  models. Hand-written stubs only prove the handler agrees with itself: the ALB
  harness happily exercised a call the live API rejects.

## [0.5.0] - 2026-11-14

First tagged release. The module is usable end to end: one apply creates the
cluster shell and the disabled trust stores, the ceremony turns them on, and both
consumers keep their CRLs current.

### Added

- `modules/alb-mtls`: the second consumer — an ELBv2 trust store for ALB mutual
  TLS, created once against a placeholder bundle and then kept current by a sync
  Lambda triggered by `CAChainPublished` and a 24-hour schedule. CRL rotation adds
  the new CRL before removing the previous `RevocationId`, so there is never a
  window with no revocation data. Wired into the composite behind
  `enable_alb_mtls` (default `false`); `alb_trust_store_arn` is an output.
- `scripts/verify_live_control_plane.sh`: a $0, no-HSM smoke test that builds a
  chain with the deployed KMS key, publishes it, emits a synthetic
  `CAChainPublished` and asserts the trust anchor and CRL come up.
  `--restore-pending` puts the stack back.
- `scripts/workflow_lint.py` and `make workflow-lint`: structural checks the
  Actions YAML can drift out of (top-level `permissions`, per-job
  `timeout-minutes`, `shell` on every composite `run:`, no expressions in action
  metadata), then `actionlint`. Runs in `make check` and in CI.
- `start_rotation_command` at the root, next to `start_bootstrap_command`.

### Changed

- `modules/hsm-ca` is workload-agnostic in name as well as in behaviour: the KMS
  key description is `<name> Intermediate CA Signing Key`, and neither the state
  machine's comment nor the CA tool's docstrings mention a consumer.
- The root README is a registry-style document — badges, cost table, three usage
  patterns, architecture, day-2 operations — with `terraform-docs` tables
  (`make docs`). `modules/hsm-ca` and `modules/roles-anywhere` gained the READMEs
  they never had.
- `.terraform.lock.hcl` is no longer tracked and `.gitignore` says so; providers
  resolve against `versions.tf`, and CI fails if a lock file is ever added. A
  Monday 08:00 UTC run resolves the newest `hashicorp/aws` with `init -upgrade`.
- CI: Terraform setup, the provider cache and `make init` moved into
  `.github/actions/setup-terraform-env`; tflint plugins and Python wheels are
  cached; every job has a `timeout-minutes`; the pinned CLI is 1.17.2 and a
  second step validates all seven configurations with 1.6.6, the floor that
  `required_version = ">= 1.6.0"` promises.
- Dependabot: one grouped `terraform` entry over `/`, `/modules/*` and
  `/examples/*`, plus `github-actions` covering the composite action.

### Fixed

- `start_bootstrap_command` and `start_rotation_command` emitted
  `--input {"mode":"BOOTSTRAP"}` unquoted, so piping to `bash` stripped the inner
  quotes and Step Functions received `{mode:BOOTSTRAP}`. Both now emit a
  single-quoted argument.
- The composite action named `${{ env.TF_VERSION }}` inside an input
  `description`, which GitHub evaluates without the `env` context — the action
  failed to load entirely. `workflow_lint.py` now rejects expressions in action
  metadata in both of its parsers.
- The composite action ran `terraform version` before the plugin cache directory
  existed, printing a CLI configuration error on every run.

## [0.4.0] - 2026-11-13

Breaking: the PKI engine and the workload consumers are separate modules joined by
an EventBridge event.

### Changed

- `modules/hsm-ca` is the workload-agnostic engine: CloudHSM cluster, KMS
  Intermediate key, artifact bucket, SSM chain, ceremony state machine. Its state
  machine no longer knows about Roles Anywhere, CRLs or any consumer: after the
  HSM is deleted, the backup is READY and the host is terminated, it ends with
  `PublishCaReadyEvent` (`eventbridge:putEvents`, `source = "cloudhsmca.pki"`,
  `detail-type = "CAChainPublished"`).
- `modules/roles-anywhere` is a consumer that takes `ca_contract` and subscribes
  to that event. Its Lambda has two triggers: `CAChainPublished` (install the
  chain, enable the anchor, import the first CRL) and `rate(24 hours)` (refresh).
  A scheduled tick before publication returns `chain-not-published` instead of
  failing.
- The repository root is a composite module (`module "hsm_ca"` +
  `module "roles_anywhere"` behind `enable_roles_anywhere`, default `true`).

### Added

- `ca_contract`: the engine's output object — key/bucket ARNs, SSM parameter
  names, signing algorithm, event bus/source/detail-type — which is the only
  thing a consumer needs.
- `allowed_kms_signer_role_arns`: the key policy matches signers by
  `aws:PrincipalArn` under the account-root principal, defaulting to
  `arn:aws:iam::<account>:role/<name>-*`, so a consumer can sign CRLs without the
  engine referencing it.
- `examples/standalone-hsm-ca`: the engine alone, for ALB/API Gateway mTLS, VPN
  or internal TLS.

### Removed

- `ReadCaBundle`, `UpdateTrustAnchor`, `EnableTrustAnchor` and `ImportOrUpdateCrl`
  from the engine's state machine, and every `rolesanywhere:*`, `ssm:GetParameter`
  and `lambda:InvokeFunction` permission that served them.

## [0.3.0] - 2026-11-13

Breaking: the repository is a single root module, and one `terraform apply`
deploys the whole PKI.

### Changed

- `modules/pki-ceremony` and `modules/roles-anywhere` are merged into the
  repository root (`main.tf`, `ceremony.tf`, `roles_anywhere.tf`,
  `crl_issuer_lambda.tf`, `statemachine.asl.json.tftpl`, `scripts/`, `tests/`).
  The KMS key, IAM roles and trust anchor are wired by resource reference, not by
  cross-stack variables or name guesses.
- `examples/01-pki-ceremony` + `examples/02-roles-anywhere` become
  `examples/complete` and `examples/auto-bootstrap`, each calling `source = "../../"`.

### Added

- A **disabled placeholder trust anchor**: a throwaway `tls` self-signed
  certificate satisfies `CreateTrustAnchor`, so the first apply no longer waits
  for a ceremony, and `ignore_changes = [source, enabled]` keeps later plans from
  reverting the real chain.
- The ceremony's activation tail: `ReadCaBundle` → `UpdateTrustAnchor` →
  `EnableTrustAnchor` → `ImportOrUpdateCrl`. A success now leaves a trust anchor
  with the real Root + Intermediate chain, enabled, with a CRL imported.
- `var.auto_bootstrap` (default `false`) and `scripts/run_ceremony_and_wait.sh`:
  with `true`, apply starts the ceremony and polls it, failing with the
  execution's cause. The waiter is idempotent on the published bundle.
- `Module = "cloudhsmca"` on every resource.

### Removed

- The `hashicorp/awscc` dependency, `awscc_rolesanywhere_crl`, and the
  `crl_management_mode` / `crl_pem_path` / `auto_bootstrap_crl` /
  `crl_bootstrap_generation` variables: the Lambda is the only CRL owner and the
  ceremony imports the first CRL.
- The SSM `data` source and its precondition on the trust anchor, and the
  `intermediate_kms_key_arn` / `backup_guard_role_names` cross-stack inputs.

## [0.2.0] - 2026-11-13

Breaking: the two-phase `ceremony_mode` toggle is gone. The ceremony is its own
module and the runtime module is a pure consumer, applied once. The repository is
laid out as `modules/pki-ceremony` + `modules/roles-anywhere`, with
`examples/01-pki-ceremony` and `examples/02-roles-anywhere` in deployment order.

### Removed

- `var.ceremony_mode`, `aws_cloudhsm_v2_hsm`, the ephemeral ceremony
  `aws_instance`, the ceremony host IAM/SG/profile, and every
  `count = var.ceremony_mode ? … : 0` guard and `[0]` index in the module.
- The module's `aws_kms_key`, CloudHSM cluster, VPC inputs, certificate SSM
  parameters, and `scripts/` directory — all moved to `modules/pki-ceremony`.
- `examples/hsm-ceremony` and `examples/steady-state`.

### Added

- `modules/pki-ceremony`: the foundation (cluster shell, **KMS Intermediate
  key**, artifact bucket, SSM hand-over, IAM) plus a Step Functions workflow that
  creates an HSM, runs the ceremony, deletes the HSM, and verifies a READY backup
  before succeeding. Its key policy matches the ceremony host and the runtime
  module's CRL role by `aws:PrincipalArn` under the account root, so neither
  module depends on the other's apply order and KMS never has to resolve a role
  that does not exist yet.
- `modules/pki-ceremony/tests/`: ASL graph invariants, the CA-chain harness and
  the ceremony script harness (moved from the module's tests), plus `run-all.sh`.
- `examples/01-pki-ceremony` (foundation + state machine) and
  `examples/02-roles-anywhere` (single-apply consumer).

### Changed

- The runtime module takes `intermediate_kms_key_arn` and reads the chain from
  SSM unconditionally: no phases, one apply, and a `precondition` that fails with
  the ceremony command when the chain is missing.

## [0.1.0] - 2026-11-13

First cut of the module and its offline verification harnesses.

### Added

- `terraform-aws-rolesanywhere-hsm-ca`: two-phase PKI module for IAM Roles
  Anywhere. Phase 1 (`ceremony_mode = true`) provisions a CloudHSM
  `hsm2m.medium` cluster in FIPS mode plus an ephemeral SSM-only Amazon Linux
  2023 host that generates the non-exportable Root CA key, self-signs the Root
  CA and signs the Intermediate CA; phase 2 destroys the HSM and provisions the
  trust anchor, workload roles and profiles.
- KMS asymmetric `SIGN_VERIFY` Intermediate CA whose key policy allows only
  `MessageType=DIGEST` signing with the algorithm that matches the key spec.
- S3 artifact bucket with versioning and Object Lock; SSM hand-over parameters;
  an IAM policy denying `cloudhsm:DeleteBackup` and
  `cloudhsm:ModifyBackupAttributes`.
- Workload role trust policies scoped by `aws:SourceArn` to the trust anchor and,
  optionally, by `aws:PrincipalTag/x509Subject/OU` / `CN`.
- `scripts/kms_ca_tool.py`: CSR, certificate and CRL construction by TBS
  splicing, with `kms`, `hsm` (`cloudhsm-cli`) and `local` (tests only) signers.
- `scripts/hsm_ceremony.sh.tftpl`: CloudHSM Client SDK 5 ceremony orchestration,
  idempotent through the SSM ceremony state.
- CRL refresh Lambda (`rate(24 hours)`) that signs a DER TBSCertList with KMS and
  imports it as PEM through `rolesanywhere:ImportCrl`.
- `awscc_rolesanywhere_crl` for declarative CRL ownership
  (`crl_management_mode = "awscc"`), with a handler interlock so the Lambda and
  Terraform cannot both own the CRL object.
- `tests/`: three offline harnesses (crypto chain, CRL handler, ceremony
  script), each verified against `openssl`, plus `tests/run-all.sh`.
- Repository scaffolding: root README, Apache-2.0 LICENSE, Makefile, tflint and
  pre-commit configuration, CI workflow, Dependabot, CODEOWNERS, SECURITY.md.

### Notes

- `hashicorp/aws` exposes no `aws_rolesanywhere_crl` resource in 5.x or 6.x; the
  CRL is managed through `hashicorp/awscc` or the service API.
- `ImportCrl` requires the CRL in PEM, while the signature is over the DER
  TBSCertList; both code paths build and verify DER, then wrap.
