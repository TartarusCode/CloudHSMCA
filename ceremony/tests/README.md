# Tests

Offline harnesses for the ceremony stack. None of them needs an AWS account, an
HSM, or credentials.

```bash
make ceremony-test        # or: ceremony/tests/run-all.sh
```

## `asl_invariants.py`

Renders `statemachine.asl.json.tftpl` with the same `templatefile` call Terraform
makes and walks the result as a graph (58 states, 16 tasks). It asserts the
properties the design depends on, because none of them is visible to
`terraform validate`:

| check | why it matters |
|---|---|
| every Task catches `States.ALL` | a botched ceremony must not leave the HSM billing |
| cleanup reaches `deleteHsm` **and** `terminateInstances` | both halves of the teardown |
| every Catch path ends in a `Fail` | no silent stop |
| failure routes into cleanup keep `$.error`, cleanup never writes it | the reported error is the real one |
| `describeInstanceInformation` precedes both `sendCommand` states, gated on `PingStatus == Online` | EC2 `running` is not SSM `Online`; otherwise `InvalidInstanceId` |
| one `CreateHsm` with `BackupId`, one without | rotation restores; bootstrap does not |
| `$.mode` is honoured, an unknown value refused, the cluster state used when absent | explicit intent beats inference, but inference must work |
| a READY backup gates both the restore and the completion | the Root key must be escrowed before success |
| `Hsms[0]` absent before success | deletion, not just the API call |

It also renders both script templates and runs `bash -n` on them.

## `crypto/test_kms_ca_tool.sh`

Drives `scripts/kms_ca_tool.py` through the full chain with a local key standing
in for KMS and for the HSM (`--signer local`), then hands every artifact to
`openssl`: `spki-from-point` byte-identical to `openssl pkey -pubout -outform
DER`, root self-signature, CSR signature, the Intermediate issued by the root,
the clientAuth leaf, a DER CRL that `openssl crl -verify` accepts, and the two
refusal paths (tampered CSR, undefined extension).

## `ceremony/run.sh`

Renders `scripts/hsm_ceremony.sh.tftpl` — the script the workflow runs on the
ephemeral host — with `terraform console`, syntax-checks it, then executes it
end to end against stubs for `cloudhsm-cli`, the AWS CLI, `dnf`, `curl`,
`systemctl` and `uv`. The `cloudhsm-cli` stub really signs and returns base64
`r||s`, exactly as Client SDK 5 does, so the tool's DER conversion is exercised.
Everything else is real: `jq`, `openssl`, the CA tool, both OpenSSL profiles. The
run must reach `COMPLETE` and the resulting chain must verify outside the script.

## What none of this covers

The live control plane: CloudHSM cluster activation timing, `configure-cli`
against a real hsm2m.medium ENI, KMS's enforcement of the key-policy conditions,
and Roles Anywhere's acceptance of the CRL. The first real bootstrap is the test
for those; the failure paths are built to fail loudly and tear down rather than
leave an HSM billing.
