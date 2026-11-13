# Terraform module repository tasks.
#
# The repository holds two peer modules and one example per deployment step:
#
#   modules/pki-ceremony    the foundation + the Root CA ceremony (Step Functions)
#   modules/roles-anywhere  the runtime: trust anchor, profiles, roles, CRL
#   examples/01-pki-ceremony   instantiates modules/pki-ceremony
#   examples/02-roles-anywhere instantiates modules/roles-anywhere
#
# MODULE and CEREMONY are variables so the targets keep working if a third module
# is added.
#
# Every target that needs providers depends on `init`, which initialises all the
# configurations sequentially in one recipe. `make -j4 check` then runs the
# independent gates in parallel: with -j the inits would race each other, and
# each configuration would download its own copy of aws and awscc.

MODULE   ?= modules/roles-anywhere
CEREMONY ?= modules/pki-ceremony
TF       ?= terraform
EXAMPLES := $(patsubst %/main.tf,%,$(wildcard examples/*/main.tf))
CONFIGS  := $(MODULE) $(CEREMONY) $(EXAMPLES)

# One provider cache shared by every configuration: a copy per configuration
# otherwise, and a fresh clone downloads them once per directory. It lives inside
# the working tree so it works unconfigured, and is gitignored. Override it with
# `make TF_PLUGIN_CACHE_DIR=/var/cache/tf check`.
TF_PLUGIN_CACHE_DIR ?= $(CURDIR)/.terraform-plugin-cache
export TF_PLUGIN_CACHE_DIR

.DEFAULT_GOAL := help
.PHONY: help init fmt fmt-check validate examples ceremony-validate lint docs \
        test ceremony-test check clean cache-clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

init: ## terraform init every configuration, sequentially, into one provider cache
	@mkdir -p "$(TF_PLUGIN_CACHE_DIR)"
	@set -e; for d in $(CONFIGS); do \
	  printf '  init %s\n' "$$d"; \
	  $(TF) -chdir=$$d init -backend=false -input=false -no-color >/dev/null; \
	done

fmt: ## Rewrite formatting in place
	$(TF) fmt -recursive

fmt-check: ## Fail if anything is unformatted (what CI runs)
	$(TF) fmt -recursive -check -diff

validate: init ## terraform validate modules/roles-anywhere
	$(TF) -chdir=$(MODULE) validate -no-color

examples: init ## Validate every example against its module
	@set -e; for d in $(EXAMPLES); do \
	  echo "== $$d"; \
	  $(TF) -chdir=$$d validate -no-color; \
	done

ceremony-validate: init ## terraform validate modules/pki-ceremony
	$(TF) -chdir=$(CEREMONY) validate -no-color

lint: ## tflint the whole tree (needs tflint + the aws ruleset plugin)
	@command -v tflint >/dev/null 2>&1 || { \
	  echo "tflint not installed: https://github.com/terraform-linters/tflint"; exit 1; }
	tflint --init
	tflint --recursive --format compact

docs: ## Regenerate a module's input/output tables (needs terraform-docs)
	@command -v terraform-docs >/dev/null 2>&1 || { \
	  echo "terraform-docs not installed: https://terraform-docs.io"; exit 1; }
	for m in $(MODULE) $(CEREMONY); do \
	  terraform-docs markdown table --output-file README.md --output-mode inject $$m; \
	done

test: init ## Run modules/roles-anywhere's harnesses (no AWS account needed)
	bash $(MODULE)/tests/run-all.sh

ceremony-test: init ## ASL invariants, CA chain, ceremony script (offline)
	bash $(CEREMONY)/tests/run-all.sh

# `make -j4 check`: init runs once, then fmt-check and lint start immediately
# while the rest wait on it. Nothing here writes shared state -- the two harness
# suites run in different directories -- so the slots are safe to fill.
check: fmt-check lint validate examples ceremony-validate test ceremony-test ## Everything CI runs
	@echo
	@echo "check: OK"

clean: ## Remove local Terraform working directories
	find . -type d -name .terraform -prune -exec rm -rf {} +
	rm -rf $(MODULE)/tests/lambda/__pycache__ $(CEREMONY)/tests/__pycache__

cache-clean: ## Remove the shared provider cache (it is only a cache)
	rm -rf "$(TF_PLUGIN_CACHE_DIR)"
