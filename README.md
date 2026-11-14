# cloudhsmca

A hardware-backed internal PKI, built for roughly **$20/year** instead of the
~$400/month of ACM Private CA:

- the **offline Root CA private key** is generated inside an ephemeral AWS
  CloudHSM (`hsm2m.medium`, FIPS mode) with `EXTRACTABLE=false`, self-signs the
  Root certificate, signs the Intermediate CSR, and is deleted with the HSM — the
  encrypted cluster backup AWS keeps automatically is what escrows it;
- the **Intermediate CA** is an always-online AWS KMS asymmetric key
  (`SIGN_VERIFY`, ECC), so its private key never leaves AWS's FIPS 140-3 Level 3
  fleet;
- consumers turn certificates into whatever they need: temporary AWS credentials
  (IAM Roles Anywhere), an mTLS trust store (ALB, API Gateway), a VPN, or plain
  PEMs for internal TLS.

| | steady-state cost |
|---|---|
| KMS asymmetric key (`SIGN_VERIFY`, ECC) | ~$1/month |
| Lambda, S3, SSM, Step Functions, EventBridge | cents |
| CloudHSM | **$0/hr** — no HSM exists outside a ceremony run (~$1.50/hr for one) |

## Two modules and one contract

```
modules/hsm-ca            the PKI engine — knows nothing about workloads
  ceremony.tf             cluster shell, KMS Intermediate key, ceremony host,
                          state machine, auto_bootstrap
  statemachine.asl...     bootstrap / rotation / cleanup / PublishCaReadyEvent
  scripts/                kms_ca_tool.py, hsm_ceremony.sh, profiles
        │
        │  SSM: /<name>/pki/{root_ca,intermediate_ca,ca_bundle}.pem
        │  EventBridge: source=cloudhsmca.pki  detail-type=CAChainPublished
        ▼
modules/roles-anywhere    one consumer among many
  roles_anywhere.tf       placeholder trust anchor, workload roles, profiles
  crl_issuer_lambda.tf    activation + 24h CRL refresh (one Lambda, two triggers)
```

`modules/hsm-ca` emits `ca_contract` — ARNs, SSM parameter names, the artifact
bucket, the signing algorithm and the event contract. A consumer needs nothing
else, and the engine never references a consumer, so the dependency graph is a
tree instead of a cycle.

The repository **root** is a turnkey composite (`module "hsm_ca"` +
`module "roles_anywhere"`, the latter behind `enable_roles_anywhere = true`).
Source the root for the all-in-one stack, or source the two modules independently
when they belong in separate states — `examples/standalone-hsm-ca` is the engine
alone.

## One apply, zero circular dependencies

`CreateTrustAnchor` needs a certificate bundle, but the real chain only exists
after a ceremony that itself needs the cluster and the KMS key to exist first.
Waiting for the chain made the first apply a two-pass affair.

Instead:

1. `terraform apply` lands in well under a minute. The consumer creates its trust
   anchor **DISABLED with a placeholder bundle** (a throwaway `tls` self-signed
   certificate, one year, CA:TRUE) and `lifecycle { ignore_changes = [source,
   enabled] }` so no later plan can revert the chain or disable a working anchor.
2. The operator (or `auto_bootstrap = true`) runs the ceremony: HSM up, Root key
   generated, Root + Intermediate signed, HSM deleted, backup verified, host
   terminated.
3. The last state, `PublishCaReadyEvent`, emits `CAChainPublished`.
4. The consumer's Lambda installs the real chain (`UpdateTrustAnchor`), enables
   the anchor (`EnableTrustAnchor`) and imports a CRL — all from the event, with
   no Terraform resource crossing the module boundary.

```json
{
  "source": "cloudhsmca.pki",
  "detail-type": "CAChainPublished",
  "detail": {
    "ca_name": "corp-pki",
    "cluster_id": "cluster-…",
    "intermediate_kms_key_arn": "arn:aws:kms:…:key/…",
    "ca_bundle_ssm_param": "/corp-pki/pki/ca_bundle.pem",
    "root_ca_ssm_param": "/corp-pki/pki/root_ca.pem",
    "intermediate_ca_ssm_param": "/corp-pki/pki/intermediate_ca.pem",
    "artifacts_bucket": "corp-pki-pki-…"
  }
}
```

Any other consumer — ALB mTLS, API Gateway, a VPN gateway — subscribes to the
same event and reads the same SSM parameters. Nothing in this repository has to
change for it.

## Quick start

Composite (PKI + Roles Anywhere), fast path:

```bash
cd examples/complete
$EDITOR main.tf              # your VPC + private subnet, subjects, tags, profiles
terraform init && terraform apply          # ~45 s

terraform output -raw start_bootstrap_command | bash
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
```

The event fires at the end of that execution; the trust anchor is ENABLED and has
a CRL a few seconds later (`aws rolesanywhere get-trust-anchor --trust-anchor-id
$(terraform output -raw trust_anchor_id)`).

Engine only (mTLS, VPN, internal TLS):

```bash
cd examples/standalone-hsm-ca
terraform init && terraform apply
terraform output -raw start_bootstrap_command | bash
```

One command that also waits for the ceremony:
`examples/auto-bootstrap` (`auto_bootstrap = true`), which polls the execution and
fails the apply with its cause if the ceremony fails.

Issue a workload certificate with the KMS Intermediate CA:

```bash
python3 modules/hsm-ca/scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$(terraform output -raw intermediate_kms_key_arn)" \
  --issuer-cert intermediate_ca.pem --csr workload.csr --days 90 --out workload.pem
```

The leaf gets `basicConstraints=critical,CA:FALSE`,
`keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth`, SKI and AKI.

## Who may sign with the Intermediate key

The key policy names the account root as principal and matches signers by
`aws:PrincipalArn`: the ceremony host plus `allowed_kms_signer_role_arns`, which
defaults to `arn:aws:iam::<account>:role/<name>-*`. That is what lets a consumer
module sign CRLs or leaf certificates without the engine referencing it — and
without KMS having to resolve (or rewrite to an AROA id) a role principal. Each
signer still needs its own identity-policy grant under the same digest-only
conditions; the Roles Anywhere Lambda's policy shows the shape.

## Workload role hardening (Roles Anywhere consumer)

Each role's trust policy allows only `rolesanywhere.amazonaws.com`, only for this
trust anchor (`ArnEquals aws:SourceArn`), and optionally only for a given
certificate subject: `allowed_subject_ou` / `allowed_subject_cn` become
`StringEquals`/`StringLike` conditions on `aws:PrincipalTag/x509Subject/OU` and
`/CN`. `sts:TagSession` is what makes those tags arrive; `sts:SetSourceIdentity`
is granted alongside it.

## The CRL

`hashicorp/aws` has no `aws_rolesanywhere_crl` resource (5.100.0 and 6.73.0
schemas both checked) and this repository does not depend on `hashicorp/awscc`:
one Lambda owns the CRL, with two triggers.

- **`CAChainPublished`** — install the chain, enable the anchor, import the first
  CRL. Activation completes before any workload can connect, so an enabled anchor
  never rejects everything for want of a revocation list.
- **`rate(24 hours)`** — re-sign and re-import. On a schedule tick before the
  first ceremony the bundle still reads `PENDING-CEREMONY`, and the handler
  returns `{"skipped": "chain-not-published"}` instead of failing.

**ImportCrl takes PEM.** The API says so outright — *"In order to be properly
imported, a CRL must be in PEM format"* — which is why the CloudFormation
`CrlData` is a String. The signature is over the DER `TBSCertList`; the payload is
PEM. The handler reads the stored CRL back and compares SHA-256 with what it
signed, so "the API accepted it" becomes evidence.

## CloudHSM backup protection

The offline Root CA key exists in exactly one place after a ceremony: the
encrypted cluster backup. `cloudhsm:DeleteBackup` and
`cloudhsm:ModifyBackupAttributes` are denied account-wide and attached to the two
roles that can manage CloudHSM in the engine (the ceremony host and the state
machine); `cloudhsm_backup_guard_policy_arn` is exposed so other principals can
be covered.

## Layout

```
.
├── main.tf variables.tf outputs.tf versions.tf   composite: hsm_ca + roles_anywhere
├── modules/
│   ├── hsm-ca/          engine: cluster, KMS key, ceremony, SSM, bucket, event
│   └── roles-anywhere/  consumer: trust anchor, profiles, roles, CRL Lambda
├── tests/               five offline harnesses (see tests/README.md)
└── examples/
    ├── complete/          composite, auto_bootstrap = false
    ├── auto-bootstrap/    composite, auto_bootstrap = true
    └── standalone-hsm-ca/ engine only (mTLS / VPN / TLS)
```

## Testing

Five offline harnesses, **no AWS account, no HSM, no credentials**:

| harness | proves |
|---|---|
| `tests/module` | the engine's variable-only locals the way plan computes them, both `auto_bootstrap` paths, the `Module` tag, the signer override, three validations |
| `tests/asl_invariants.py` | the rendered state machine: cleanup on `States.ALL`, cause preservation, SSM readiness, the backup gate, and that it ends with `PublishCaReadyEvent` and has **no** `rolesanywhere` coupling |
| `tests/crypto` | the whole X.509 chain — root, Intermediate, leaf, CRL — with local stand-ins for KMS and CloudHSM |
| `tests/ceremony` | `hsm_ceremony.sh.tftpl` rendered by Terraform and executed against a stub `cloudhsm-cli` that really signs (base64 `r\|\|s`, as Client SDK 5 returns) |
| `tests/lambda` | the consumer's Lambda: the `CAChainPublished` activation (update + enable + import), the scheduled refresh, the no-chain skip, the no-chain activation failure, and the CRL itself via openssl |

```bash
make init        # one init per configuration, into one shared provider cache
make -j4 check   # fmt, validate (all three modules), examples, lint, all five harnesses
```

`TF_PLUGIN_CACHE_DIR` defaults to `.terraform-plugin-cache` in the working tree
(gitignored) so every configuration shares one copy of the providers.
`make clean` keeps it; `make cache-clean` drops it.

What the harnesses cannot prove — CloudHSM control-plane timing, KMS policy
enforcement, Roles Anywhere accepting the CRL, `UpdateTrustAnchor` itself — is
listed in [`tests/README.md`](tests/README.md).

## Requirements

- Terraform >= 1.6; providers `hashicorp/aws >= 5.67`, `hashicorp/archive`,
  `hashicorp/random`, `hashicorp/tls`
- A VPC with private subnets (the CloudHSM ENIs and the ephemeral host live
  there; no NAT, no bastion, no SSH — access is SSM Session Manager only)
- Region support for CloudHSM `hsm2m.medium` in **FIPS** mode
- For `auto_bootstrap = true`: the AWS CLI on the machine running apply

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache-2.0 — see [LICENSE](LICENSE).
