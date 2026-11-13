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
terraform-aws-rolesanywhere-hsm-ca/   the runtime — consumes a CA chain, one apply
  ├── versions.tf variables.tf main.tf roles_anywhere.tf
  ├── crl_issuer_lambda.tf outputs.tf
  └── tests/    two offline harnesses (see tests/README.md)
ceremony/                             the foundation + the ceremony (Step Functions)
  ├── main.tf variables.tf outputs.tf
  ├── statemachine.asl.json.tftpl     bootstrap, rotation, cleanup
  ├── scripts/  kms_ca_tool.py, hsm_ceremony.sh.tftpl, rotate_intermediate.sh.tftpl, *.cnf.tftpl
  └── tests/    ASL graph, CA chain, ceremony script (see ceremony/README.md)
examples/
  ├── complete/    step 1: cluster shell, KMS key, state machine
  └── runtime/     step 2: trust anchor, profiles, roles, CRL
.github/workflows/ci.yml   fmt, validate, tflint, python, harnesses, examples
```

One way to produce the chain, and one way to consume it:

1. **`ceremony/`** (the foundation, one apply) creates the CloudHSM cluster shell,
   the KMS Intermediate key, the artifact bucket, the SSM hand-over parameters and
   a Step Functions workflow. No HSM exists after apply.
2. **The workflow** creates an HSM (restoring the cluster backup on a rotation),
   runs the ceremony on an ephemeral host, deletes the HSM, and returns only after
   confirming the HSM is gone and a READY backup exists.
3. **`terraform-aws-rolesanywhere-hsm-ca`** (the runtime, one apply) reads the
   published chain from SSM and builds the trust anchor, workload roles, profiles
   and CRL.

Nothing deletes what it created in an earlier phase, and no apply has to be
re-run because a later step exists.

## Quick start

The runbook for both stacks lives in
[`ceremony/README.md`](ceremony/README.md) and
[`terraform-aws-rolesanywhere-hsm-ca/README.md`](terraform-aws-rolesanywhere-hsm-ca/README.md).

```bash
# 1. foundation + state machine (no HSM is created by apply)
cd examples/complete
$EDITOR main.tf            # your VPC + private subnet, subjects, tags
terraform init && terraform apply

# 2. the ceremony itself: ~$1.50/hr for the length of one execution
eval "$(terraform output -raw start_bootstrap_command)"
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED

# 3. the runtime, one apply, consuming the chain
cd ../runtime
terraform init && terraform apply \
  -var intermediate_kms_key_arn="$(terraform -chdir=../complete output -raw intermediate_kms_key_arn)"
```

Both examples point at their stack by path (`../../ceremony`,
`../../terraform-aws-rolesanywhere-hsm-ca`), so clone the repo and work in place,
or replace the `source` with a git ref once the stacks are tagged.

```bash
# issue a workload certificate with the KMS Intermediate CA
python3 ../../ceremony/scripts/kms_ca_tool.py sign-leaf-csr \
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

```bash
make init        # one init per configuration, into one shared provider cache
make -j4 check   # ~40 s: init once, then the independent gates in parallel
```

`TF_PLUGIN_CACHE_DIR` defaults to `.terraform-plugin-cache` in the working tree
(gitignored) so the four configurations share one copy of `aws` + `awscc`
(~900 MB) instead of four. `make clean` keeps it; `make cache-clean` drops it.

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
