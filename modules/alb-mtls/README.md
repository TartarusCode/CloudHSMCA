# alb-mtls

The second consumer of [`../hsm-ca`](../hsm-ca): an **ELBv2 trust store** for ALB
mutual TLS, kept in step with the CA through the same `CAChainPublished` event the
Roles Anywhere consumer uses.

```hcl
module "alb_mtls" {
  source = "…/modules/alb-mtls"

  ca_contract = module.hsm_ca.ca_contract
  # name = "payments"   # optional: alb-mtls/<name>/ in the artifact bucket
}

resource "aws_lb_listener" "https" {
  # …
  mutual_authentication {
    mode             = "verify"
    trust_store_arn  = module.alb_mtls.trust_store_arn
  }
}
```

## One apply, no circular dependency

`elbv2:CreateTrustStore` needs a PEM bundle in S3 at creation time, but the real
chain only exists after a ceremony. So the module uploads a **throwaway
self-signed certificate** (`tls_self_signed_cert.placeholder`, CA:TRUE, one year)
to `s3://<artifacts>/alb-mtls/<name>/ca_bundle.pem`, creates the trust store
against that exact object version, and lets the sync Lambda replace both:

- `ignore_changes = [content, etag]` on the S3 object, so a plan never restores
  the placeholder;
- `ignore_changes = [ca_certificates_bundle_s3_object_version]` on the trust
  store, so a plan never reverts the Lambda's `ModifyTrustStore`.

## The sync Lambda

One function, two triggers, and the role is named `<ca_name>-alb-mtls-sync` on
purpose — the CA's key policy matches signers by
`aws:PrincipalArn = arn:aws:iam::<account>:role/<ca_name>-*`, so no resource has to
cross the module boundary.

| trigger | behaviour |
|---|---|
| `cloudhsmca.pki` / `CAChainPublished` | read the chain from `ca_contract.ca_bundle_ssm_param`, upload it, `ModifyTrustStore` to that object version, then rotate the CRL |
| `rate(24 hours)` | rotate the CRL; if the chain still reads `PENDING-CEREMONY`, return `{"skipped": "chain-not-published"}` without touching S3 or ELBv2 |

**CRL rotation has no unrevoked window.** The handler signs a fresh PEM CRL, uploads
it, calls `AddTrustStoreRevocations` with the new object version, and only then
calls `RemoveTrustStoreRevocations` on the previous `RevocationIds`. Doing it the
other way round would leave a window in which the trust store has no revocation
data at all.

Revoked serials come from `var.revoked_serials_ssm_param` (JSON, same shape the
Roles Anywhere consumer reads from S3); unset means an empty CRL.

## Inputs that matter

| input | why |
|---|---|
| `ca_contract` | every ARN, SSM path and the event contract; nothing is guessed |
| `name` | S3 prefix only (`alb-mtls/<name>/`); empty = the CA's name |
| `trust_store_name` | ELBv2 caps this at 32 characters; empty = `<ca_name>-alb-mtls`, and a `precondition` says so instead of an opaque API error |
| `revoked_serials_ssm_param` | where the revoked serials live |
| `crl_validity_days` | must exceed the refresh cadence (default 7 vs 24 h) |

## Tests

```bash
modules/alb-mtls/tests/run-all.sh          # or: make test
```

- `tests/module/smoke.sh` — the locals the way plan computes them (S3 prefix,
  trust store name, the role name that must keep the `<ca_name>-` prefix) and the
  32-character rule.
- `tests/lambda/test_lambda.py` — the handler extracted from `sync_lambda.tf` with
  stubs for SSM/S3/KMS/ELBv2: activation (bundle version → `ModifyTrustStore`),
  the pre-publication skip, the add-then-remove ordering, the activation-without-
  chain failure, and the CRL itself verified with `openssl`.

What these cannot prove: that `CreateTrustStore` accepts the placeholder bundle,
that `ModifyTrustStore` switches a live trust store, and that ELBv2 accepts the
CRL. Those are live-only; `scripts/verify_live_control_plane.sh` covers the Roles
Anywhere equivalents for $0.
