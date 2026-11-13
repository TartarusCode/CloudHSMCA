# Tests

Three offline harnesses. None of them needs an AWS account, an HSM, or
credentials: `tests/run-all.sh` is the whole suite and what CI runs.

```bash
make test          # or: tests/run-all.sh
```

`tests/ceremony` renders the template with `terraform console`, which loads the
module configuration, so the module's providers must be installed; the harness
runs `terraform init -backend=false` itself when `.terraform/providers` is
missing. Nothing else needs Terraform.

What each one actually proves, and what it explicitly does not:

## `crypto/test_kms_ca_tool.sh`

Drives `scripts/kms_ca_tool.py` through the full chain with a local key standing
in for KMS and for the HSM (`--signer local`), then hands every artifact to
`openssl`:

| check | why it matters |
|---|---|
| `spki-from-point` byte-identical to `openssl pkey -pubout -outform DER` | the HSM never exports a public key; this reconstruction is the only source |
| root self-signature verifies, `CA:TRUE`, `keyCertSign, cRLSign` | the Root profile the ceremony asserts |
| CSR signature verifies, `CA:TRUE, pathlen:0` requested | the Intermediate CSR carries its profile |
| intermediate issued by root verifies | the splice produces a chain-valid certificate, not just a parseable one |
| clientAuth leaf verifies with `-untrusted` | the Roles Anywhere leaf profile |
| DER CRL verifies with `openssl crl -verify`, `crlNumber` present | X.509 CRL shape |
| tampered CSR refused, message names the reason | proof-of-possession is enforced, not just attempted |
| undefined extension refused | the `.cnf` profile is the single definition |

## `lambda/test_lambda.py`

Extracts the handler **from the `<<-PY` heredoc in `crl_issuer_lambda.tf`**, i.e.
the bytes that get zipped, and runs it against a boto3 stand-in backed by a real
P-384 key. Asserts: the CRL openssl-verifies against its issuer, the AKI is the
issuer's SKI (so the chain matches), both revoked serials and their reason codes
survive, the blob handed to `import_crl` is **PEM** (the API rejects raw DER),
the `GetCrl` round-trip is compared by SHA-256, and the handler refuses to import
when `CRL_OWNER=awscc`. Also covers the empty-revocation-set CRL.

## `ceremony/run.sh`

Renders `scripts/hsm_ceremony.sh.tftpl` with `terraform console` (the same
`templatefile` Terraform runs), syntax-checks the result with `bash -n`, then
executes it end-to-end with stubs for `cloudhsm-cli`, the AWS CLI, `dnf`, `curl`,
`systemctl`, `configure-cli` and `uv`. The `cloudhsm-cli` stub really signs:
`crypto sign ecdsa` returns base64 `r||s`, exactly as Client SDK 5 does, so the
tool's DER conversion is exercised. Everything else is real — `jq`, `openssl`,
the CA tool, both rendered OpenSSL profiles.

It asserts the ceremony reaches `COMPLETE` and that the resulting chain verifies
outside the script, plus the SSM parameter and S3 key names the phase-2 apply
consumes.

## What none of this covers

The live control plane: CloudHSM cluster activation timing, `configure-cli`
against a real hsm2m.medium ENI, KMS's own enforcement of the key-policy
conditions, and Roles Anywhere's acceptance of the CRL. Those need an account.
The harnesses are built so that every failure they *can* see is loud, and the
Lambda additionally proves the ImportCrl round trip at run time so a
service-side rejection surfaces in its log instead of silently revoking nothing.
