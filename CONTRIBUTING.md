# Contributing

## Conventions

- **Signed commits.** `commit.gpgsign = true`; history is the operators' work, so
  no tool or agent attribution in messages.
- **No secrets in the tree.** No `.pem`, `.key`, `.csr`, `.tfvars` or state files
  are tracked; `.gitignore` covers them. `crl.pem` is an input, not an artifact
  of this repo.
- **Comments describe the current behaviour**, never the previous one — including
  the comment you are editing.
- **Every claim in a README is a test** where the environment allows it; where it
  does not (CloudHSM control-plane timing, service-side CRL acceptance), the
  README says so instead of implying coverage.

## The local gate

```bash
make init        # one init per configuration, into one shared provider cache
make -j4 check   # fmt-check, validate, examples, lint, and all five harnesses
```

`make check` is what CI runs (`fmt-check`, validate on the module and both
examples, `tflint`, and `tests/run-all.sh`). `make -j4 check` runs the independent
gates in parallel: `init` is a single target, so the slots cannot race each other
in the provider cache.

`TF_PLUGIN_CACHE_DIR` defaults to `.terraform-plugin-cache` in the working tree
(gitignored); point it elsewhere with a make variable if you prefer. `make clean`
removes the `.terraform` directories and keeps the cache; `make cache-clean`
drops the cache too.

## Changing the ceremony or the CA tooling

The scripts under `scripts/` run on an ephemeral host inside a VPC with no
inbound access, so a mistake there is discovered at the worst moment. Their
harnesses execute the real artifacts — the script rendered by `terraform
console`, the Python tool against local keys, the CloudHSM CLI and AWS CLI against
stubs — and every certificate and CRL is verified with `openssl`. If you change a
signing path, add the assertion to the harness in the same change rather than
relying on `terraform validate`, which never renders a script's behaviour.
