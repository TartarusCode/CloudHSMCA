# CloudHSMCA

A hardware-backed internal PKI for **AWS IAM Roles Anywhere**, built so the
certificate authority costs about **$2/month** instead of the ~$400/month of
ACM Private CA.

The trick is splitting the two jobs a CA does between a *billed-by-the-hour* HSM
and a *billed-by-the-month* KMS key:

| Component | Role | Steady-state cost |
|---|---|---|
| AWS CloudHSM `hsm2m.medium`, FIPS mode | Root CA private key, non-exportable | **$0/hr** — the HSM is deleted after the ceremony; AWS keeps the encrypted cluster backup |
| AWS KMS asymmetric key (`SIGN_VERIFY`, ECC) | Intermediate CA private key, never exportable | ~$1/month |
| IAM Roles Anywhere | trust anchor, profiles, CRL | free |
| Lambda + S3 + SSM | CRL refresh, artifacts, chain hand-over | cents |

Nothing here holds a private key in a file, in git, or in Terraform state: the
Root key exists only inside the HSM (and afterwards in its encrypted backup), and
the Intermediate key only inside KMS.

## Repository layout

```
terraform-aws-rolesanywhere-hsm-ca/   the runtime module — consumes a CA chain
  ├── versions.tf variables.tf main.tf
  ├── ceremony_hsm.tf roles_anywhere.tf crl_issuer_lambda.tf outputs.tf
  ├── scripts/  kms_ca_tool.py, hsm_ceremony.sh.tftpl, *.cnf.tftpl
  └── tests/    three offline harnesses (see tests/README.md)
ceremony/                             produces the CA chain (Step Functions)
  ├── main.tf variables.tf outputs.tf
  ├── statemachine.asl.json.tftpl     the ceremony: bootstrap, rotation, cleanup
  ├── scripts/  bootstrap + Intermediate rotation entrypoints
  └── tests/    ASL graph invariants (see ceremony/README.md)
examples/
  ├── hsm-ceremony/    phase 1: HSM + ephemeral signing host
  └── steady-state/    phase 2: trust anchor, profiles, roles, CRL
.github/workflows/ci.yml   fmt, validate, tflint, python, harnesses, examples
```

Two ways to produce the chain exist in this repository, deliberately:

* `terraform-aws-rolesanywhere-hsm-ca` with `ceremony_mode` — the module creates
  the HSM and host itself, in two applies. Simple, but Terraform acts as a state
  machine and an interrupted ceremony leaves an HSM billing.
* `ceremony/` — Step Functions borrows the HSM, runs the ceremony, deletes it,
  and publishes the chain. The runtime module then applies once, as a consumer.
  This is the recommended shape; see [`ceremony/README.md`](ceremony/README.md).

## Quick start

The module is a two-phase state machine; `ceremony_mode` decides which phase you
are in, and the full runbook lives in
[`terraform-aws-rolesanywhere-hsm-ca/README.md`](terraform-aws-rolesanywhere-hsm-ca/README.md).

```bash
# 1. ceremony: ~$1.50/hr for a few hours
cd examples/hsm-ceremony
$EDITOR main.tf            # your VPC + private subnet, subjects, tags
terraform init && terraform apply
terraform output -raw ceremony_ssm_connect_command | bash   # watch it finish

# 2. steady state: destroys the HSM, brings up Roles Anywhere
cd ../steady-state
terraform init && terraform apply
```

Both examples point at the module by path (`../../terraform-aws-rolesanywhere-hsm-ca`),
so clone the repo and work in place, or replace the `source` with a git ref once
the module is tagged.

```bash
# issue a workload certificate with the KMS Intermediate CA
python3 ../../terraform-aws-rolesanywhere-hsm-ca/scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$(terraform output -raw intermediate_kms_key_arn)" \
  --issuer-cert intermediate_ca.pem --csr workload.csr --days 90 --out workload.pem
```

## Testing

```bash
make test      # or: terraform-aws-rolesanywhere-hsm-ca/tests/run-all.sh
```

Three harnesses, **no AWS account required**: the X.509 chain built with local
stand-ins for KMS/CloudHSM, the CRL Lambda extracted from its Terraform heredoc
and run against a real key, and the whole HSM ceremony script rendered by
Terraform and executed against a stub `cloudhsm-cli` that really signs
(base64 `r||s`, exactly as Client SDK 5 returns). Every certificate and CRL they
produce is verified with `openssl`. See
[`tests/README.md`](terraform-aws-rolesanywhere-hsm-ca/tests/README.md) for what
each one proves and what it cannot.

`make check` runs the format check, `terraform validate`, tflint and the
harnesses — the same set CI runs.

## Requirements

- Terraform >= 1.6, providers: `hashicorp/aws >= 5.67`, `hashicorp/awscc`,
  `hashicorp/archive`, `hashicorp/random`
- `awscc_rolesanywhere_crl` is the only Terraform resource that can manage an
  IAM Roles Anywhere CRL, so the AWSCC provider is configured in the root module
- Region support for CloudHSM `hsm2m.medium` in **FIPS** mode
- For the ceremony host: nothing but a private subnet — no NAT, no bastion, no
  SSH. Access is SSM Session Manager only.

## Conventions

- **Signed commits.** `commit.gpgsign = true`; history is the operators' work, so
  no tool or agent attribution in messages.
- **No secrets in the tree.** No `.pem`, `.key`, `.csr`, `.tfvars` or state files
  are tracked; `.gitignore` covers them. `crl.pem` is an input, not an artifact
  of this repo.
- **Comments describe the current behaviour**, never the previous one.
- **Every claim in a README is a test** where the environment allows it; where it
  does not (CloudHSM control-plane timing, service-side CRL acceptance), the
  README says so instead of implying coverage.

## License

Apache-2.0 — see [LICENSE](LICENSE).
