# Security policy

This repository builds a certificate authority. Treat findings here as
high-impact even when they look cosmetic: a wrong X.509 extension, a weak key
usage, or a CRL that stops being refreshed can silently widen who can obtain AWS
credentials.

## Reporting

Report suspected vulnerabilities privately through GitHub's *Security → Report a
vulnerability* on this repository. Do not open a public issue for:

- anything that could let a workload certificate be issued or accepted without
  the intended subject constraints,
- a path that could export the Root or Intermediate private key,
- an authentication or authorization bypass in the Lambda, IAM roles, or trust
  policy,
- a dependency or supply-chain issue in the ceremony tooling.

Include the affected file (and line), the Terraform phase (`ceremony` or
`steady-state`) and what an attacker gains. A working `terraform plan` diff or a
failing harness case is the most useful evidence.

## Scope and design claims worth testing

- Private keys never exist outside KMS and CloudHSM. If you find a code path
  that writes one, that is the bug this repository exists to prevent.
- The Root key survives only in the CloudHSM cluster backup; the module denies
  `cloudhsm:DeleteBackup` and `cloudhsm:ModifyBackupAttributes` account-wide.
- Workload roles are assumable only by `rolesanywhere.amazonaws.com`, only for
  this trust anchor, and optionally only for a given certificate OU/CN.
- Terraform state holds the CloudHSM ceremony bootstrap passwords (SSM
  `SecureString` values). Use an encrypted, access-controlled backend — a
  finding that reports "state contains secrets" is expected and documented, not
  a vulnerability, but an unencrypted backend is.

## Supported versions

`main` only; the module is consumed by path or git ref, so pin a commit or tag.
