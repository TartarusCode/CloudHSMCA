# Terraform module repository tasks.
#
# The repository is one root module (registry-style layout) plus one example per
# execution mode:
#
#   .                          the whole PKI: cluster shell, ceremony workflow,
#                              KMS Intermediate key, trust anchor, roles, CRL
#   examples/complete          auto_bootstrap = false (fast apply, ceremony out of band)
#   examples/auto-bootstrap    auto_bootstrap = true  (one command, waits for the ceremony)
#
# Every target that needs providers depends on `init`, which initialises the
# module and the examples sequentially in one recipe. `make -j4 check` then runs
# the independent gates in parallel: with -j the inits would race each other, and
# each configuration would download its own copy of the providers.

MODULE   ?= .
TF       ?= terraform
EXAMPLES := $(patsubst %/main.tf,%,$(wildcard examples/*/main.tf))
CONFIGS  := $(MODULE) $(EXAMPLES)

# One provider cache shared by every configuration: a copy per configuration
# otherwise, and a fresh clone downloads them once per directory. It lives inside
# the working tree so it works unconfigured, and is gitignored. Override it with
# `make TF_PLUGIN_CACHE_DIR=/var/cache/tf check`.
TF_PLUGIN_CACHE_DIR ?= $(CURDIR)/.terraform-plugin-cache
export TF_PLUGIN_CACHE_DIR

.DEFAULT_GOAL := help
.PHONY: help init fmt fmt-check validate examples lint docs test check clean cache-clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

init: ## terraform init the module and the examples, into one provider cache
	@mkdir -p "$(TF_PLUGIN_CACHE_DIR)"
	@set -e; for d in $(CONFIGS); do \
	  printf '  init %s\n' "$$d"; \
	  $(TF) -chdir=$$d init -backend=false -input=false -no-color >/dev/null; \
	done

fmt: ## Rewrite formatting in place
	$(TF) fmt -recursive

fmt-check: ## Fail if anything is unformatted (what CI runs)
	$(TF) fmt -recursive -check -diff

validate: init ## terraform validate the root module
	$(TF) -chdir=$(MODULE) validate -no-color

examples: init ## Validate every example against the module
	@set -e; for d in $(EXAMPLES); do \
	  echo "== $$d"; \
	  $(TF) -chdir=$$d validate -no-color; \
	done

lint: ## tflint the whole tree (needs tflint + the aws ruleset plugin)
	@command -v tflint >/dev/null 2>&1 || { \
	  echo "tflint not installed: https://github.com/terraform-linters/tflint"; exit 1; }
	tflint --init
	tflint --recursive --format compact

docs: ## Regenerate the input/output tables (needs terraform-docs)
	@command -v terraform-docs >/dev/null 2>&1 || { \
	  echo "terraform-docs not installed: https://terraform-docs.io"; exit 1; }
	terraform-docs markdown table --output-file README.md --output-mode inject $(MODULE)

test: init ## Run every offline harness (no AWS account needed)
	bash tests/run-all.sh

# `make -j4 check`: init runs once, then fmt-check and lint start immediately
# while the rest wait on it. Nothing here writes shared state.
check: fmt-check lint validate examples test ## Everything CI runs
	@echo
	@echo "check: OK"

clean: ## Remove local Terraform working directories
	find . -type d -name .terraform -prune -exec rm -rf {} +
	rm -rf tests/lambda/__pycache__ tests/__pycache__

cache-clean: ## Remove the shared provider cache (it is only a cache)
	rm -rf "$(TF_PLUGIN_CACHE_DIR)"
