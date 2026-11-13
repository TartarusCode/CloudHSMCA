# terraform-aws-rolesanywhere-hsm-ca

A hardware-backed internal PKI for **AWS IAM Roles Anywhere** that costs about
**$2/month** instead of the ~$400/month of ACM Private CA, by splitting the two
jobs a CA does between a *billed by the hour* HSM and a *billed by the month*
KMS key.

| Component | Role | Steady-state cost |
|---|---|---|
| AWS CloudHSM `hsm2m.medium`, FIPS mode | Root CA private key (non-exportable) | **$0/hr** — HSM deleted in phase 2, encrypted cluster backup retained |
| AWS KMS asymmetric key `SIGN_VERIFY` | Intermediate CA private key (never exportable) | ~$1/month |
| AWS IAM Roles Anywhere | trust anchor + profiles + CRL | free |
| Lambda + S3 + SSM | CRL refresh, artifacts, chain hand-over | cents |

Total steady state: **~$1–2/month**, and **~$1.50/hour** only while the ceremony
runs (a few hours per Root CA rotation, i.e. per 10 years).

```
                    phase 1 (ceremony_mode = true)               phase 2 (false)
  ┌─────────────────────────────────────────────┐    ┌────────────────────────────────┐
  │ CloudHSM cluster + 1 HSM  ──► Root CA key   │    │ HSM + EC2 destroyed            │
  │ ephemeral EC2 (SSM only)  ──► signs root +  │───►│ Root + Intermediate PEM from   │
  │ KMS Intermediate key      ──► CSR          │SSM │ SSM  ──► trust anchor          │
  │ certificates ──► SSM + S3                   │    │ profiles, roles, CRL Lambda    │
  └─────────────────────────────────────────────┘    └────────────────────────────────┘
```

## Files

```
versions.tf               Terraform/provider constraints
variables.tf              inputs (ceremony_mode, subjects, workload_profiles, ...)
main.tf                   KMS Intermediate key, S3 artifact bucket, SSM hand-over, backup guard
ceremony_hsm.tf           CloudHSM cluster/HSM, ceremony host + IAM, rendered profile uploads
roles_anywhere.tf         trust anchor, workload roles, profiles, awscc CRL (or Lambda-owned CRL)
crl_issuer_lambda.tf      24h EventBridge schedule + Lambda that signs/imports the CRL
outputs.tf                trust_anchor_arn, profile_arns, ceremony_ssm_connect_command, ...
scripts/kms_ca_tool.py    all X.509 construction: CSR, certificates, CRL (KMS | CloudHSM | local)
scripts/hsm_ceremony.sh.tftpl   cloud-init ceremony orchestration (Amazon Linux 2023)
scripts/root_ca.cnf.tftpl       Root CA X.509 profile (read by the tool AND openssl)
scripts/intermediate_ca.cnf.tftpl  Intermediate CA profile (pathlen:0)
```

## Runbook

### 0. Prerequisites

* a VPC with at least one **private** subnet (no NAT needed for the HSM path)
* `terraform >= 1.6`, and the AWS CLI on the machine that applies (phase 2
  bootstraps the CRL with `aws lambda invoke`)
* IAM permissions for CloudHSM, KMS, S3, SSM, Lambda, IAM, Roles Anywhere

### 1. Root CA ceremony (phase 1)

```hcl
module "pki" {
  source        = "…/terraform-aws-rolesanywhere-hsm-ca"
  name          = "corp-pki"
  ceremony_mode = true
  vpc_id        = "vpc-…"
  private_subnet_ids = ["subnet-…"]
  workload_profiles = {}
}
```

```bash
terraform apply          # ~20-30 min: CloudHSM cluster + HSM + ceremony host
terraform output -raw ceremony_ssm_connect_command | bash
```

Then, on the ceremony host (the script has usually finished by itself):

```bash
sudo tail -f /var/log/pki-ceremony.log      # watch the ceremony
aws ssm get-parameter --name /corp-pki/pki/ceremony/state --query Parameter.Value --output text
# → COMPLETE
openssl x509 -in /opt/pki/root_ca.pem -noout -subject -fingerprint -sha256
```

The script, in order: installs CloudHSM Client SDK 5 `cloudhsm-cli`, points it at
the single HSM ENI, activates the cluster, creates a crypto user, generates the
Root key **inside the HSM with `extractable=false sign=true`**, rebuilds the Root
public key from the HSM-reported EC point, self-signs the Root certificate with
`cloudhsm-cli crypto sign ecdsa`, builds the Intermediate CSR from the KMS key,
signs that with the HSM root, asserts the X.509 profile with `openssl`, and
publishes the chain to SSM + S3. No private key is ever written to disk.

If it fails halfway, the state parameter reads `FAILED`; the log names the step.
The HSM key label is fixed per cluster, so a retry that hits "label already
exists" needs a fresh HSM (`terraform apply -replace` on the HSM) rather than a
re-run — this is the one manual gate that keeps the root key single-use.

### 2. Steady state (phase 2)

```hcl
  ceremony_mode = false
  workload_profiles = {
    "batch" = {
      managed_policy_arns  = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
      allowed_subject_ou   = "platform"
      allowed_subject_cn   = "batch-*"
      subject_condition_operator = "StringLike"
    }
  }
```

```bash
terraform apply
#  - destroys the HSM and the ceremony host (CloudHSM keeps the encrypted backup)
#  - reads Root + Intermediate from SSM, creates the trust anchor
#  - creates one IAM role + profile per workload
#  - invokes the CRL Lambda once so a CRL exists before the first request
```

### 3. Issue a workload certificate

```bash
openssl ecparam -name prime256v1 -genkey -noout -out workload.key
openssl req -new -key workload.key -subj "/CN=batch-01/OU=platform/O=Example Corp" -out workload.csr

python3 scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$(terraform output -raw intermediate_kms_key_arn)" \
  --issuer-cert intermediate_ca.pem --csr workload.csr \
  --days 90 --out workload.pem
```

The leaf gets `basicConstraints=critical,CA:FALSE`,
`keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth`, SKI and AKI.

Workload credential retrieval:

```bash
aws_signing_helper credential-process \
  --certificate workload.pem --private-key workload.key \
  --trust-anchor-arn "$(terraform output -raw trust_anchor_arn)" \
  --profile-arn <profile arn> --role-arn <role arn>
```

### 4. Revoke

```bash
echo '{"revoked":[{"serial":"0x1f2e…","reason":"key_compromise"}]}' \
  | aws s3 cp - s3://<artifact bucket>/revocations/revoked.json

# crl_management_mode = "awscc"  (default): regenerate and re-apply
python3 scripts/kms_ca_tool.py generate-crl --signer kms \
  --kms-key-id "$(terraform output -raw intermediate_kms_key_arn)" \
  --issuer-cert intermediate_ca.pem --revoked-file revoked.json \
  --days 7 --out crl.pem
terraform apply -var 'crl_pem_path=crl.pem'

# crl_management_mode = "lambda": invoke now instead of waiting for the schedule
aws lambda invoke --function-name "$(terraform output -raw crl_issuer_function_name)" \
  --payload '{"reason":"manual"}' out.json && cat out.json
```

In `lambda` mode the same Lambda runs every 24 hours; it rebuilds the CRL from
that JSON, signs it with the KMS Intermediate CA, imports it as PEM, then reads
the stored CRL back and compares SHA-256 with what it signed. In `awscc` mode the
CRL is a tracked resource, so a stale `crl.pem` shows up in `terraform plan`
rather than silently expiring.

## Design notes worth reading before you change anything

**`aws_rolesanywhere_crl` does not exist in hashicorp/aws — `awscc_rolesanywhere_crl` does.** Verified against the provider schemas: hashicorp/aws **5.100.0** and **6.73.0** expose only `aws_rolesanywhere_profile` and `aws_rolesanywhere_trust_anchor`; the CRL resource is in the **AWSCC** provider (`AWS::RolesAnywhere::CRL`). The module therefore has two mutually exclusive owners, chosen by `crl_management_mode`:

| mode | owner | refresh |
|---|---|---|
| `awscc` (default) | `awscc_rolesanywhere_crl` from `var.crl_pem_path` | regenerate the PEM + `terraform apply` |
| `lambda` | the scheduled Lambda (`rolesanywhere:ImportCrl`) | every 24 hours, hands-off |

Only one may own it: a second owner leaves an *enabled* CRL whose `nextUpdate`
expires while a newer one also exists, and Roles Anywhere evaluates every enabled
CRL. The Lambda refuses to import when `crl_management_mode = "awscc"`, and the
schedule is not created at all in that mode.

**ImportCrl takes PEM, not DER.** The API reference says plainly: *"In order to
be properly imported, a CRL must be in PEM format."* That is also why `CrlData`
is a CloudFormation `String` and can be fed from a file. The signature is still
over the DER `TBSCertList` (X.509 requires that), so both tools produce a DER
CRL, verify it as DER, and hand the service PEM.

**`customer_master_key_spec`, not `key_spec`.** `key_spec` exists in aws 5.x but
is absent from 6.x; `customer_master_key_spec` is accepted by both, which is what
the `>= 5.67.0, < 7.0.0` constraint needs.

**Signing without a local private key.** `cryptography` can only sign with a
private-key object, so every artifact is built twice: once with a throwaway key
to obtain the exact TBS bytes, then spliced back together from the original TBS,
the real `AlgorithmIdentifier`, and the signature produced by KMS
(`MessageType='DIGEST'`) or the HSM. The splice never re-encodes the TBS, and
each artifact is re-parsed and its signature verified against the issuer's public
key before it is written.

**CloudHSM specifics (SDK 5).** `cloudhsm-cli crypto sign ecdsa` returns
**base64 of the raw `r||s`** concatenation, so the tool converts to DER. The
public key is never exported: it is rebuilt from the `ec-point` attribute the HSM
reports at key generation (`spki-from-point`), and that helper is unit-checked
against OpenSSL byte-for-byte.

**Extension profiles have one definition.** `scripts/*.cnf.tftpl` are real
OpenSSL configs (`openssl x509 -req -extfile root_ca.cnf -extensions v3_root_ca`
works on them) *and* are parsed by `kms_ca_tool.py`. An extension the profiles do
not define fails loudly instead of being silently dropped.

**The Root key lives only in the CloudHSM backup.** `aws_iam_policy.cloudhsm_backup_guard`
denies `cloudhsm:DeleteBackup` and `cloudhsm:ModifyBackupAttributes` account-wide
(backup IDs do not exist at plan time, and a scoped resource would be bypassed by
any new backup). Attach it to every principal that can touch CloudHSM —
`backup_guard_role_names` does it for you.

**S3 Object Lock defaults to GOVERNANCE/30 days.** Use
`object_lock_mode = "COMPLIANCE"` for certificate artifacts if your auditors need
immutability; note that COMPLIANCE retention cannot be shortened, including for
CRL objects.

**Bootstrap secrets land in Terraform state.** The CloudHSM admin and crypto-user
passwords are `random_password` values written to SSM SecureString; use an
encrypted, access-controlled backend.

## Verification status

Exercised locally (not against AWS — no cloud resources were created):

* `terraform validate` clean on `hashicorp/aws 6.73.0`; provider schemas for
  5.100.0 and 6.73.0 both inspected.
* `kms_ca_tool.py`, full chain with a local key standing in for KMS/HSM: root
  self-signature, KMS-style CSR, Intermediate issued by root, clientAuth leaf,
  DER CRL — every artifact verified by `openssl verify` / `openssl crl -verify`;
  tampered CSR refused; unknown extension refused; `spki-from-point` byte-identical
  to `openssl pkey -pubout -outform DER`.
* `crl_issuer_lambda.tf` handler run against a real P-384 key: the DER CRL it
  builds verifies with `openssl crl -verify`, the empty-revocation-set variant too,
  and the blob handed to `import_crl` is asserted to be PEM; the handler refuses
  to run when `crl_management_mode = "awscc"`.
* `awscc_rolesanywhere_crl` is accepted by `terraform validate` against
  `hashicorp/awscc 1.110.0`, with a precondition that fails with the exact
  `generate-crl` command when no PEM has been supplied.
* `hsm_ceremony.sh.tftpl`: rendered by Terraform, then executed end-to-end with
  `cloudhsm-cli`, the AWS CLI and KMS emulated (the emulated HSM really signs, in
  base64 `r||s`, exactly as SDK 5 does) — reached `COMPLETE` and the resulting
  chain verifies in OpenSSL.

Assumed, not verified in this environment: the live CloudHSM control-plane
behaviour (cluster activation timing, `configure-cli` against an hsm2m.medium
ENI, quorum/MFA options), and Roles Anywhere's acceptance of the CRL — the code
asserts the ImportCrl round trip at run time, so a mismatch fails loudly in the
Lambda log instead of silently revoking nothing.
