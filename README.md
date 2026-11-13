# cloudhsmca

A hardware-backed internal PKI for **AWS IAM Roles Anywhere**, built for roughly
**$20/year** instead of the ~$400/month of ACM Private CA:

- the **offline Root CA private key** is generated inside an ephemeral AWS
  CloudHSM (`hsm2m.medium`, FIPS mode) with `EXTRACTABLE=false`, self-signs the
  Root certificate, signs the Intermediate CSR, and is then deleted with the HSM —
  the encrypted cluster backup AWS keeps automatically is what escrows it;
- the **Intermediate CA** is an always-online AWS KMS asymmetric key
  (`SIGN_VERIFY`, ECC), so its private key never leaves AWS's FIPS 140-3 Level 3
  fleet;
- **IAM Roles Anywhere** turns certificates into temporary AWS credentials, with
  a scheduled Lambda keeping a CRL imported and fresh.

**One module, one apply.** The whole foundation, the Step Functions ceremony and
the Roles Anywhere runtime are in this directory, so there is nothing to pass
between stacks and no second pass.

| | steady-state cost |
|---|---|
| KMS asymmetric key (`SIGN_VERIFY`, ECC) | ~$1/month |
| IAM Roles Anywhere, Lambda, S3, SSM, Step Functions | cents |
| CloudHSM | **$0/hr** — no HSM exists outside a ceremony run (~$1.50/hr for one) |

## How one apply is possible

`CreateTrustAnchor` needs a certificate bundle, but the real chain only exists
after a ceremony that itself needs the cluster, the KMS key and the trust anchor
to exist first. The usual answer is two applies.

This module creates the trust anchor **DISABLED with a placeholder bundle**
(a throwaway self-signed certificate from the `tls` provider) and lets the
ceremony activate it:

1. `apply` lands in well under a minute: cluster shell, KMS key, bucket, SSM
   parameters, IAM, state machine, trust anchor (DISABLED), profiles and roles.
2. The workflow runs the ceremony and deletes the HSM.
3. Still inside the same execution it fetches the published chain
   (`ReadCaBundle`), installs it (`UpdateTrustAnchor`), enables the anchor
   (`EnableTrustAnchor`) and imports the first CRL (`ImportOrUpdateCrl`).

`lifecycle { ignore_changes = [source, enabled] }` is what makes that safe: no
later plan can revert the chain Terraform created or disable a working anchor.

Two ways to run step 2, chosen by `var.auto_bootstrap`:

| `auto_bootstrap` | `terraform apply` | who runs the ceremony |
|---|---|---|
| `false` (default) | ~45 s, trust anchor DISABLED | the operator: `terraform output -raw start_bootstrap_command \| bash` |
| `true` | 15–45 min, returns with the PKI working | `terraform_data.auto_bootstrap` → `scripts/run_ceremony_and_wait.sh`, which polls the execution and fails the apply with its cause |

The waiter is idempotent: if `/<name>/pki/ca_bundle.pem` already holds a chain,
it does nothing, so a re-apply never starts a second HSM.

## Layout

```
.
├── versions.tf                    aws, archive, random, tls (nothing else)
├── variables.tf                   network, key material, subjects, workloads
├── main.tf                        artifact bucket (Object Lock), backup deny-list
├── ceremony.tf                    cluster shell, KMS key, host role, state machine,
│                                  auto_bootstrap
├── roles_anywhere.tf              placeholder trust anchor, workload roles, profiles
├── crl_issuer_lambda.tf           CRL signing Lambda + 24h refresh
├── outputs.tf
├── statemachine.asl.json.tftpl    bootstrap / rotation / activation / cleanup
├── scripts/
│   ├── kms_ca_tool.py             DER/TBS splicing CA tool (local, KMS, CloudHSM signers)
│   ├── hsm_ceremony.sh.tftpl      what runs on the ephemeral host
│   ├── run_ceremony_and_wait.sh   the auto_bootstrap waiter
│   └── *.cnf.tftpl                the OpenSSL profiles
├── tests/                         five offline harnesses (see tests/README.md)
└── examples/
    ├── complete/                  auto_bootstrap = false
    └── auto-bootstrap/            auto_bootstrap = true
```

## Quick start

```bash
cd examples/complete
$EDITOR main.tf              # your VPC + private subnet, subjects, tags
terraform init && terraform apply          # ~45 s

terraform output -raw start_bootstrap_command | bash
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
```

When that execution succeeds the trust anchor holds the real Root + Intermediate
chain, is ENABLED, and has a CRL. For a sandbox where one command should do all
of it, use `examples/auto-bootstrap` (`auto_bootstrap = true`).

Issue a workload certificate with the KMS Intermediate CA:

```bash
python3 scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$(terraform output -raw intermediate_kms_key_arn)" \
  --issuer-cert intermediate_ca.pem --csr workload.csr --days 90 --out workload.pem
```

The leaf gets `basicConstraints=critical,CA:FALSE`,
`keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth`, SKI and AKI.
Workloads then call `aws_signing_helper credential-process` — the
`rolesanywhere_update_env` output prints a ready-made command.

## Workload role hardening

Each role's trust policy allows only `rolesanywhere.amazonaws.com`, only for this
trust anchor (`ArnEquals aws:SourceArn`), and optionally only for a given
certificate subject: `allowed_subject_ou` / `allowed_subject_cn` become
`StringEquals`/`StringLike` conditions on `aws:PrincipalTag/x509Subject/OU` and
`/CN`. `sts:TagSession` is what makes those tags arrive; `sts:SetSourceIdentity`
is granted alongside it.

## The CRL

`hashicorp/aws` has no `aws_rolesanywhere_crl` resource (5.100.0 and 6.73.0
schemas both checked), and this module does not depend on `hashicorp/awscc` for
it: the CRL is owned by the Lambda.

- The ceremony's `ImportOrUpdateCrl` state imports the first CRL, so an enabled
  anchor never rejects everything for want of a revocation list.
- A 24-hour EventBridge schedule re-signs and re-imports it from
  `revocations/revoked.json` in the artifact bucket.
- **ImportCrl takes PEM.** The API says so outright — *"In order to be properly
  imported, a CRL must be in PEM format"* — which is also why the CloudFormation
  `CrlData` is a String. The signature is over the DER `TBSCertList`; the payload
  is PEM. The handler reads the stored CRL back and compares SHA-256 with what it
  signed, so "the API accepted it" becomes evidence.
- A CRL whose `nextUpdate` has passed rejects every certificate, which is why the
  schedule is not optional and `crl_validity_days` (7) is well above 24 h.

## CloudHSM backup protection

The offline Root CA key exists in exactly one place after a ceremony: the
encrypted cluster backup. `cloudhsm:DeleteBackup` and
`cloudhsm:ModifyBackupAttributes` are denied account-wide and attached to the two
roles here that can manage CloudHSM (the ceremony host and the state machine);
`cloudhsm_backup_guard_policy_arn` is exposed so other principals can be covered.

## Testing

Five offline harnesses, **no AWS account, no HSM, no credentials**:

| harness | proves |
|---|---|
| `tests/module` | the variable-only locals the way plan computes them, both `auto_bootstrap` paths, the `Module` tag, four validations — `validate` never evaluates locals |
| `tests/lambda` | the CRL handler extracted from `crl_issuer_lambda.tf`, signed with a real P-384 key, verified by openssl, round-tripped through a stubbed `GetCrl` |
| `tests/crypto` | the whole X.509 chain — root, Intermediate, leaf, CRL — with local stand-ins for KMS and CloudHSM |
| `tests/ceremony` | `hsm_ceremony.sh.tftpl` rendered by Terraform and executed against a stub `cloudhsm-cli` that really signs (base64 `r\|\|s`, as Client SDK 5 returns) |
| `tests/asl_invariants.py` | the rendered state machine walked as a graph: cleanup on `States.ALL`, cause preservation, SSM readiness, the backup gate, and the activation tail |

```bash
make init        # one init per configuration, into one shared provider cache
make -j4 check   # ~25 s: fmt, validate, examples, lint, all five harnesses
```

`TF_PLUGIN_CACHE_DIR` defaults to `.terraform-plugin-cache` in the working tree
(gitignored) so every configuration shares one copy of the providers.
`make clean` keeps it; `make cache-clean` drops it.

What the harnesses cannot prove — CloudHSM control-plane timing, KMS policy
enforcement, Roles Anywhere accepting the CRL — is listed in
[`tests/README.md`](tests/README.md).

## Requirements

- Terraform >= 1.6; providers `hashicorp/aws >= 5.67`, `hashicorp/archive`,
  `hashicorp/random`, `hashicorp/tls`
- A VPC with private subnets (the CloudHSM ENIs and the ephemeral host live
  there; no NAT, no bastion, no SSH — access is SSM Session Manager only)
- Region support for CloudHSM `hsm2m.medium` in **FIPS** mode
- For `auto_bootstrap = true`: the AWS CLI on the machine running apply

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache-2.0 — see [LICENSE](LICENSE).
