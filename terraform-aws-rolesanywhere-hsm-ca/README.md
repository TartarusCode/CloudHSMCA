# terraform-aws-rolesanywhere-hsm-ca

The **runtime** half of a hardware-backed PKI for IAM Roles Anywhere: it takes a
certificate chain that already exists and builds the trust anchor, the per-workload
IAM roles and profiles, and the CRL machinery — in **one apply**.

It does not create a CA. The chain and the KMS Intermediate key come from
[`ceremony/`](../ceremony), a Step Functions workflow that borrows a CloudHSM for
the length of one ceremony. That split is why this module has no phase flag: a
boolean toggle would make Terraform a temporal state machine, with
`count = … ? 1 : 0` guards, `[0]` index guards, and a second apply that deletes
what the first created.

| | cost |
|---|---|
| KMS asymmetric key (`SIGN_VERIFY`, ECC) | ~$1/month — created by `ceremony/` |
| IAM Roles Anywhere, Lambda, S3, SSM | cents |
| CloudHSM | **$0/hr** — no HSM exists outside a ceremony run |

## Inputs it needs from the ceremony

```
/<name>/pki/root_ca.pem            published by the workflow
/<name>/pki/intermediate_ca.pem
/<name>/pki/ca_bundle.pem           Root then Intermediate
/<name>/pki/ceremony/state         COMPLETE when the ceremony succeeded
intermediate_kms_key_arn           `terraform output -raw intermediate_kms_key_arn`
```

`name` must match the ceremony stack's `name`; the SSM paths are derived from it.

## Usage

```hcl
module "pki" {
  source = "…/terraform-aws-rolesanywhere-hsm-ca"

  name                     = "corp-pki"
  intermediate_kms_key_arn = "arn:aws:kms:…:key/…"

  crl_management_mode = "lambda"        # hands-off daily CRL, see below

  workload_profiles = {
    batch = {
      managed_policy_arns        = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
      allowed_subject_ou         = "platform"
      allowed_subject_cn         = "batch-*"
      subject_condition_operator = "StringLike"
    }
  }
}
```

```bash
terraform apply     # one pass: trust anchor, roles, profiles, CRL
```

Issuing a leaf, with the ceremony stack's tooling:

```bash
python3 ../ceremony/scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$(terraform output -raw …)" \
  --issuer-cert intermediate_ca.pem --csr workload.csr --days 90 --out workload.pem
```

The leaf gets `basicConstraints=critical,CA:FALSE`,
`keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth`, SKI and AKI.

Workload credential retrieval uses `aws_signing_helper credential-process` with
the certificate, key, trust anchor ARN, profile ARN and role ARN — the
`rolesanywhere_update_env` output prints a ready-made example.

## Workload role hardening

Each role's trust policy allows only `rolesanywhere.amazonaws.com`, only for
**this** trust anchor (`ArnEquals aws:SourceArn`), and optionally only for a given
certificate subject: `allowed_subject_ou` / `allowed_subject_cn` become
`StringEquals`/`StringLike` conditions on `aws:PrincipalTag/x509Subject/OU` and
`/CN`. `sts:TagSession` is what makes those tags arrive; `sts:SetSourceIdentity`
is granted alongside it.

## CRL: exactly one owner

`hashicorp/aws` has **no** `aws_rolesanywhere_crl` (5.100.0 and 6.73.0 schemas
both checked) — the resource is `awscc_rolesanywhere_crl` in the AWSCC provider.

| mode | owner | refresh |
|---|---|---|
| `awscc` (default) | `awscc_rolesanywhere_crl` from `var.crl_pem_path` | regenerate the PEM, re-apply |
| `lambda` | the scheduled Lambda (`rolesanywhere:ImportCrl`) | every 24 hours, hands-off |

Only one may own it: a second owner leaves an *enabled* CRL whose `nextUpdate`
expires while a newer one also exists, and Roles Anywhere evaluates every enabled
CRL. The Lambda refuses to run when `awscc` owns the object, and the schedule is
not created in that mode.

**ImportCrl takes PEM, not DER.** The API reference says it outright: *"In order
to be properly imported, a CRL must be in PEM format."* That is also why
`CrlData` is a CloudFormation `String`. The signature is over the DER
`TBSCertList` (X.509 requires that), so the tooling builds and verifies DER and
hands the service PEM.

In `lambda` mode the handler reads `revocations/revoked.json` from the artifact
bucket, signs, imports, then reads the stored CRL back and compares SHA-256 with
what it signed — "the API accepted it" becomes evidence.

## Design notes

**`customer_master_key_spec`, not `key_spec`.** `key_spec` exists in aws 5.x and
is gone in 6.x; `customer_master_key_spec` is accepted by both, which the
`>= 5.67.0, < 7.0.0` range needs.

**The chain is an input, and the module says so when it is missing.** The trust
anchor carries a `precondition` on the bundle: at least two certificates, and not
the `PENDING-CEREMONY` sentinel. A half-finished ceremony therefore fails at the
first resource with the command to run, instead of producing a trust anchor that
accepts nothing.

**CloudHSM backups are protected account-wide.** `cloudhsm:DeleteBackup` and
`cloudhsm:ModifyBackupAttributes` are denied on every resource, because backup ids
do not exist at plan time and a scoped deny would be bypassed by any new backup.
Attach the policy to every principal that can manage CloudHSM —
`backup_guard_role_names` does it for you, and it should include the ceremony
stack's `<name>-ceremony-host`.

**S3 Object Lock defaults to GOVERNANCE/30 days.** Use
`object_lock_mode = "COMPLIANCE"` if auditors need immutability; COMPLIANCE
retention cannot be shortened, including for CRL objects.

## Tests

```bash
make test     # or: tests/run-all.sh
```

Two offline harnesses, no AWS account — see [`tests/README.md`](tests/README.md).
The CA tooling and the ceremony are tested in
[`ceremony/tests/`](../ceremony/tests).
