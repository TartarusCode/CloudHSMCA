# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module follows
semantic versioning once it is tagged.

## [0.5.0] - 2026-11-14

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

### Changed

- `modules/hsm-ca` is fully workload-agnostic in name too: the KMS key description
  is `<name> Intermediate CA Signing Key`, and the ceremony's description mentions
  no consumer.

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
