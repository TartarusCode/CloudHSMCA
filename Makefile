# Terraform module repository tasks.
#
# MODULE selects the module directory (one module today; the variable keeps the
# targets honest if a second is added).
#
# Every target that needs providers depends on `init`, which initialises all the
# configurations sequentially in one recipe. `make -j4 check` then runs the
# independent gates in parallel: with -j the inits would race each other, and
# each configuration would download its own copy of aws and awscc.

MODULE ?= terraform-aws-rolesanywhere-hsm-ca
TF      ?= terraform
EXAMPLES := $(patsubst %/main.tf,%,$(wildcard examples/*/main.tf))
CONFIGS  := $(MODULE) ceremony $(EXAMPLES)

# One provider cache shared by every configuration: four copies of aws + awscc
# otherwise, and a fresh clone downloads them four times. It lives inside the
# working tree so it works unconfigured, and is gitignored. Override it with
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

validate: init ## terraform validate the module
	$(TF) -chdir=$(MODULE) validate -no-color

examples: init ## Validate every example against the module
	@set -e; for d in $(EXAMPLES); do \
	  echo "== $$d"; \
	  $(TF) -chdir=$$d validate -no-color; \
	done

ceremony-validate: init ## terraform validate the ceremony stack
	$(TF) -chdir=ceremony validate -no-color

lint: ## tflint the whole tree (needs tflint + the aws ruleset plugin)
	@command -v tflint >/dev/null 2>&1 || { \
	  echo "tflint not installed: https://github.com/terraform-linters/tflint"; exit 1; }
	tflint --init
	tflint --recursive --format compact

docs: ## Regenerate the module's input/output tables (needs terraform-docs)
	@command -v terraform-docs >/dev/null 2>&1 || { \
	  echo "terraform-docs not installed: https://terraform-docs.io"; exit 1; }
	terraform-docs markdown table --output-file README.md --output-mode inject $(MODULE)

test: init ## Run the module's offline harnesses (no AWS account needed)
	bash $(MODULE)/tests/run-all.sh

ceremony-test: init ## ASL invariants, CA chain, ceremony script (offline)
	bash ceremony/tests/run-all.sh

# `make -j4 check`: init runs once, then fmt-check and lint start immediately
# while the rest wait on it. Nothing here writes shared state -- the two harness
# suites run in different directories -- so the slots are safe to fill.
check: fmt-check lint validate examples ceremony-validate test ceremony-test ## Everything CI runs
	@echo
	@echo "check: OK"

clean: ## Remove local Terraform working directories
	find . -type d -name .terraform -prune -exec rm -rf {} +
	rm -rf $(MODULE)/tests/lambda/__pycache__ ceremony/tests/__pycache__

cache-clean: ## Remove the shared provider cache (it is only a cache)
	rm -rf "$(TF_PLUGIN_CACHE_DIR)"
