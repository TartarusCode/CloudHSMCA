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
make -j4 check   # fmt-check, validate, examples, lint, workflow-lint, all seven harnesses
```

`make check` is what CI runs (`fmt-check`, validate on all three modules and
every example, `tflint`, `workflow-lint`, and `tests/run-all.sh`). `make -j4 check` runs the independent
gates in parallel: `init` is a single target, so the slots cannot race each other
in the provider cache.

`TF_PLUGIN_CACHE_DIR` defaults to `.terraform-plugin-cache` in the working tree
(gitignored); point it elsewhere with a make variable if you prefer. `make clean`
removes the `.terraform` directories, any local lock files, and keeps the cache;
`make cache-clean` drops the cache too.

`.terraform.lock.hcl` is **not** tracked, and `.gitignore` says so. Providers are
constrained by `versions.tf` and resolved fresh, so CI is not frozen on one
provider set and a contributor on `darwin/arm64` does not hit hash mismatches
recorded on `linux/amd64`. `TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE=true`
is exported for the same reason: the shared cache may serve providers without
pinning their package hashes into a file that must never be committed. The
hygiene job fails the build if a lock file is ever added.

## Changing the ceremony or the CA tooling

The scripts under `modules/hsm-ca/scripts/` run on an ephemeral host inside a VPC with no
inbound access, so a mistake there is discovered at the worst moment. Their
harnesses execute the real artifacts — the script rendered by `terraform
console`, the Python tool against local keys, the CloudHSM CLI and AWS CLI against
stubs — and every certificate and CRL is verified with `openssl`. If you change a
signing path, add the assertion to the harness in the same change rather than
relying on `terraform validate`, which never renders a script's behaviour.
