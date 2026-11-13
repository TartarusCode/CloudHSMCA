# Terraform module repository tasks.
#
# MODULE selects the module directory (one module today; the variable keeps the
# targets honest if a second is added).

MODULE ?= terraform-aws-rolesanywhere-hsm-ca
TF      ?= terraform
EXAMPLES := $(wildcard examples/*/main.tf)

.DEFAULT_GOAL := help
.PHONY: help init fmt fmt-check validate lint docs test check examples clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

init: ## terraform init the module (no backend, no credentials)
	$(TF) -chdir=$(MODULE) init -backend=false -input=false -no-color

fmt: ## Rewrite formatting in place
	$(TF) fmt -recursive

fmt-check: ## Fail if anything is unformatted (what CI runs)
	$(TF) fmt -recursive -check -diff

validate: init ## terraform validate the module
	$(TF) -chdir=$(MODULE) validate -no-color

examples: ## Validate every example against the module
	@set -e; for f in $(EXAMPLES); do \
	  dir=$$(dirname $$f); \
	  echo "== $$dir"; \
	  $(TF) -chdir=$$dir init -backend=false -input=false -no-color >/dev/null; \
	  $(TF) -chdir=$$dir validate -no-color; \
	done

lint: ## tflint the whole tree (needs tflint + the aws ruleset plugin)
	@command -v tflint >/dev/null 2>&1 || { \
	  echo "tflint not installed: https://github.com/terraform-linters/tflint"; exit 1; }
	tflint --init
	tflint --recursive

docs: ## Regenerate the module's input/output tables (needs terraform-docs)
	@command -v terraform-docs >/dev/null 2>&1 || { \
	  echo "terraform-docs not installed: https://terraform-docs.io"; exit 1; }
	terraform-docs markdown table --output-file README.md --output-mode inject $(MODULE)

test: ## Run the offline harnesses (no AWS account needed)
	bash $(MODULE)/tests/run-all.sh

check: fmt-check validate lint test ## Everything CI runs
	@echo
	@echo "check: OK"

clean: ## Remove local Terraform working directories
	find . -type d -name .terraform -prune -exec rm -rf {} +
	rm -rf $(MODULE)/tests/ceremony/pylib/__pycache__ $(MODULE)/tests/lambda/__pycache__
