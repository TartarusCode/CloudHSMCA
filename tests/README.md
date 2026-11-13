# Tests

Five offline harnesses for the module. None of them needs an AWS account, an HSM,
or credentials.

```bash
make test        # or: tests/run-all.sh
```

## `module/smoke.sh`

Evaluates the module's variable-only locals the way `terraform plan` does, for
both `auto_bootstrap` paths, and asserts the `Module = "cloudhsmca"` tag wins over
a caller-supplied one.

`terraform validate` never evaluates locals, so a local that raises only when it
is actually computed passes every gate and fails at the first plan. This test was
written for one of those: `crl_pem` calling `fileexists("")` with an empty default
path, which Terraform 1.9.x reports as *"'.' is a directory, not a file"* while
1.17 tolerated it. It also checks four variable validations that must be
rejected — in **one** console invocation, because console reports every invalid
variable an expression references and each extra process costs ~7 s of provider
startup.

Locals that read a resource attribute or a data source (the state machine
definition reads the trust anchor id, the AMI and the bucket) cannot be evaluated
offline; `terraform plan` is the only test for those.

## `lambda/test_lambda.py`

Extracts the handler **from the heredoc in `crl_issuer_lambda.tf`** — the bytes
that get zipped, not a copy — and runs it against a boto3 stand-in backed by a real
P-384 key. Asserts:

| check | why |
|---|---|
| the CRL passes `openssl crl -verify` | well-formed is not chain-valid |
| AKI equals the issuer's SKI | the chain must actually match |
| both revoked serials survive | entries are encoded by hand |
| the blob handed to `import_crl` is **PEM** | the API rejects raw DER |
| `GetCrl` returns the same SHA-256 | proves the round trip, not just acceptance |
| the empty-revocation-set CRL is valid | a CRL with no entries is legal |
| the handler refuses without a trust anchor | no CRL is signed with nowhere to import it |

## `crypto/test_kms_ca_tool.sh`

Drives `scripts/kms_ca_tool.py` through the full chain with a local key standing
in for KMS and for the HSM (`--signer local`), then hands every artifact to
`openssl`: `spki-from-point` byte-identical to `openssl pkey -pubout -outform
DER`, root self-signature, CSR signature, the Intermediate issued by the root, the
clientAuth leaf, a DER CRL that `openssl crl -verify` accepts, and the two refusal
paths (tampered CSR, undefined extension).

## `ceremony/run.sh`

Renders `scripts/hsm_ceremony.sh.tftpl` — the script the workflow runs on the
ephemeral host — with `terraform console`, syntax-checks it, then executes it end
to end against stubs for `cloudhsm-cli`, the AWS CLI, `dnf`, `curl`, `systemctl`
and `uv`. The `cloudhsm-cli` stub really signs and returns base64 `r||s`, exactly
as Client SDK 5 does, so the tool's DER conversion is exercised. Everything else
is real: `jq`, `openssl`, the CA tool, both OpenSSL profiles. The run must reach
`COMPLETE` and the resulting chain must verify outside the script.

## `asl_invariants.py`

Renders `statemachine.asl.json.tftpl` with the same `templatefile` call Terraform
makes and walks the result as a graph (62 states, 20 tasks):

| check | why it matters |
|---|---|
| every Task catches `States.ALL` | a botched ceremony must not leave the HSM billing |
| cleanup reaches `deleteHsm` **and** `terminateInstances` | both halves of the teardown |
| every Catch path ends in a `Fail`, and the original cause survives | the reported error is the real one |
| `describeInstanceInformation` precedes both `sendCommand` states, gated on `PingStatus == Online` | EC2 `running` is not SSM `Online` |
| one `CreateHsm` with `BackupId`, one without | rotation restores; bootstrap does not |
| a READY backup gates both the restore and the completion | the Root key must be escrowed |
| `UpdateTrustAnchor` and `EnableTrustAnchor` precede `Succeed` | the trust anchor is created DISABLED, so this is what makes the PKI work |
| `UpdateTrustAnchor` installs `$.bundle.caBundlePem` as a `CERTIFICATE_BUNDLE` | the chain must be the one the ceremony published |
| the activation states can still reach `deleteHsm` | a failure there must not strand the HSM |

It also renders both script templates and runs `bash -n` on them.

## What none of this covers

The live control plane: CloudHSM cluster activation timing, `configure-cli`
against a real hsm2m.medium ENI, KMS's enforcement of the key-policy conditions,
Roles Anywhere's acceptance of the CRL, and the `UpdateTrustAnchor` /
`EnableTrustAnchor` calls. The first real bootstrap is the test for those; the
failure paths are built to fail loudly and tear down rather than leave an HSM
billing.
