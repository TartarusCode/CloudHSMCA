# Tests

Two offline harnesses for the runtime module. No AWS account needed.

```bash
make test        # or: tests/run-all.sh
```

## `module/smoke.sh`

Evaluates the module's variable-only locals the way `terraform plan` does.

`terraform validate` never evaluates locals, so a local that raises only when it
is actually computed passes every gate and fails at the first plan. This test was
written for one of those: `crl_pem` called `fileexists("")` with the default
empty `crl_pem_path`, which Terraform 1.9.x reports as *"'.' is a directory, not
a file"* while 1.17 tolerated it. It covers both CRL-path cases (default and
nonexistent), both CRL ownership modes, and three variable validations that must
be rejected.

Locals that read a resource attribute or an SSM data source cannot be evaluated
offline; `terraform plan` is the only test for those.

## `lambda/test_lambda.py`

Extracts the handler **from the `<<-PY` heredoc in `crl_issuer_lambda.tf`** — the
bytes that get zipped, not a copy — and runs it against a boto3 stand-in backed by
a real P-384 key. Asserts:

| check | why |
|---|---|
| the CRL passes `openssl crl -verify` | well-formed is not chain-valid |
| AKI equals the issuer's SKI | the chain must actually match |
| both revoked serials and their reason codes survive | entries are encoded by hand |
| the blob handed to `import_crl` is **PEM** | the API rejects raw DER |
| `GetCrl` returns the same SHA-256 | proves the round trip, not just acceptance |
| the empty-revocation-set CRL is valid | a CRL with no entries is legal and common |
| the handler refuses when `CRL_OWNER=awscc` | one owner for the CRL object |

The CA tooling (`kms_ca_tool.py`) and the CloudHSM ceremony live in
[`modules/pki-ceremony/tests/`](../../pki-ceremony/tests) and are tested there.
