# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module follows
semantic versioning once it is tagged.

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
