# cloudhsmca

[![ci](https://github.com/TartarusCode/CloudHSMCA/actions/workflows/ci.yml/badge.svg)](https://github.com/TartarusCode/CloudHSMCA/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A hardware-backed internal PKI for AWS — IAM Roles Anywhere, ALB mutual TLS, and
any other mTLS/VPN/TLS consumer that accepts a PEM chain — where the Root CA key
is generated inside an ephemeral AWS CloudHSM and never exists in a file. It costs
about **$2/month** at steady state instead of **$400+/month** for ACM Private CA.

| Component | Role | Steady-state cost |
|---|---|---|
| CloudHSM `hsm2m.medium`, FIPS mode | Offline **Root CA**: key generated `EXTRACTABLE=false`, HSM deleted after the ceremony; the encrypted cluster backup escrows the key | **$0/hr** (≈$1.50/hr only while a ceremony runs) |
| KMS asymmetric `ECC_NIST_P384` | Always-online **Intermediate CA**: signs leaves and CRLs inside AWS's FIPS 140-3 L3 fleet | ~$1/month |
| Step Functions, EventBridge, Lambda, S3, SSM | Ceremony orchestration and the `CAChainPublished` fan-out to consumers | cents |

## Usage

### Turnkey: PKI engine + Roles Anywhere + ALB mTLS in one apply

```hcl
module "corp_pki" {
  source = "git::https://github.com/TartarusCode/CloudHSMCA.git?ref=v0.6.0"

  name               = "corp-pki"
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"

  enable_roles_anywhere = true
  enable_alb_mtls       = true

  workload_profiles = {
    ci-runners = {
      session_duration_seconds = 3600
      managed_policy_arns      = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      allowed_subject_ou       = "CI"
    }
  }
}
```

`terraform apply` creates the cluster shell, the key, the state machine and both
trust stores **disabled**, without an HSM and without a certificate; the ceremony
activates them when it runs (see below).

### Composable: Tier-0 PKI state apart from Day-2 workload state

```hcl
# stack 1 — the PKI engine, its own state file, touched once per CA lifetime
module "hsm_ca" {
  source = "git::https://github.com/TartarusCode/CloudHSMCA.git//modules/hsm-ca?ref=v0.6.0"

  name               = "corp-pki"
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"
}

# stack 2 — consumers, their own state, reviewed and applied by workload teams
module "roles_anywhere" {
  source = "git::https://github.com/TartarusCode/CloudHSMCA.git//modules/roles-anywhere?ref=v0.6.0"

  ca_contract = module.hsm_ca.ca_contract   # or a terraform_remote_state lookup
  workload_profiles = {
    ci-runners = { managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"] }
  }
}

module "alb_mtls" {
  source = "git::https://github.com/TartarusCode/CloudHSMCA.git//modules/alb-mtls?ref=v0.6.0"

  ca_contract = module.hsm_ca.ca_contract
}
```

`ca_contract` is the whole interface: key and bucket ARNs, SSM parameter names,
the signing algorithm, and the EventBridge source/detail-type. No consumer
references a resource in the engine, and the engine references no consumer.

### First bootstrap: the commissioning CA

A Terraform-created cluster starts `UNINITIALIZED` and cannot be activated until
its cluster CSR is signed by a separate, approved commissioning CA and
`InitializeCluster` succeeds. Supply that CA in `commissioning_ca`:

```hcl
commissioning_ca = {
  certificate                = file("commissioning-ca.pem")   # public trust anchor
  key_ssm_param              = "/corp-pki/commissioning/key"  # SecureString
  signed_cluster_certificate = ""                              # or a pre-signed cert
}
```

The private key never enters Terraform state: either the ceremony reads it from
the named SSM SecureString and shreds it after signing, or you pre-sign the
cluster CSR outside the plan and pass the certificate. The certificate is
installed as the client trust anchor (`/opt/cloudhsm/etc/customerCA.crt`) before
activation. The ceremony verifies the CLI RPM checksum before it reads any
credential, and every tooling/CNF object is fetched by S3 version id.

`auto_bootstrap = true` requires `enable_bootstrap = true` (validated).

### Bootstrap: turnkey vs. operator-run ceremony

`auto_bootstrap = false` (default) — apply the stack, then start the ceremony:

```bash
terraform output -raw start_bootstrap_command | bash
aws stepfunctions describe-execution --execution-arn <arn>   # until SUCCEEDED
```

`auto_bootstrap = true` — apply runs the ceremony itself (`terraform_data` +
`scripts/run_ceremony_and_wait.sh`), polls it, and fails the apply with the
execution's cause if it fails. This holds the apply open for tens of minutes (HSM
provisioning dominates) and needs the AWS CLI on the machine running apply; see
[`examples/auto-bootstrap`](examples/auto-bootstrap).

## Architecture

```
                    terraform apply  (no HSM, no certificate yet)
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  modules/hsm-ca                                                          │
 │    CloudHSM cluster shell · KMS Intermediate key · artifact bucket       │
 │    SSM chain parameters · Step Functions state machine · event bus       │
 │  modules/roles-anywhere     trust anchor DISABLED + placeholder bundle   │
 │  modules/alb-mtls           aws_lb_trust_store + placeholder S3 bundle   │
 └──────────────────────────────────────────────────────────────────────────┘
                                   │
                    operator (or auto_bootstrap) runs the ceremony
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  Step Functions                                                          │
 │    1. CreateHsm  (hsm2m.medium, FIPS)                                    │
 │    2. Root key EXTRACTABLE=false → self-sign Root CA → sign KMS CSR      │
 │    3. verify root/intermediate/bundle are published in SSM + S3          │
 │    4. DeleteHsm  → triggers the cluster backup, billing drops to $0/hr   │
 │    5. poll DescribeBackups every 60s until READY (Root key escrowed)     │
 │    6. terminate the ceremony host, release the lease                     │
 │    7. PublishCaReadyEvent → cloudhsmca.pki / CAChainPublished            │
 └──────────────────────────────────────────────────────────────────────────┘
                                   │  EventBridge
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  subscribed consumers (zero Terraform coupling to the engine)            │
 │    roles-anywhere: UpdateTrustAnchor → EnableTrustAnchor → ImportCrl     │
 │    alb-mtls:       ModifyTrustStore(version) → AddTrustStoreRevocations  │
 │    every 24 h:     re-sign the CRL and swap it in                        │
 └──────────────────────────────────────────────────────────────────────────┘
```

Because the ceremony is the only actor that touches the HSM, no HSM or signing
host ever exists in Terraform state; because consumers activate from an event,
the first apply never waits for the ceremony and there is no circular dependency.

## Day-2 operations

Set up the environment first (all snippets assume the composite stack):

```bash
name="$(terraform output -json ca_contract | python3 -c 'import json,sys;print(json.load(sys.stdin)["name"])')"
key_arn="$(terraform output -raw intermediate_kms_key_arn)"
aws ssm get-parameter --name "/$name/pki/intermediate_ca.pem" \
  --query Parameter.Value --output text > intermediate_ca.pem
```

### Issue a workload certificate

The workload generates its own key and CSR; the private key never leaves it, and
KMS never releases the CA key.

```bash
openssl ecparam -name prime256v1 -genkey -noout -out workload.key
openssl req -new -key workload.key -subj "/OU=CI/O=Example Corp/CN=ci-runner-01" \
  -out workload.csr

python3 modules/hsm-ca/scripts/kms_ca_tool.py sign-leaf-csr \
  --signer kms --kms-key-id "$key_arn" \
  --issuer-cert intermediate_ca.pem --csr workload.csr \
  --days 90 --out workload.pem
```

The leaf carries `basicConstraints=critical,CA:FALSE`,
`keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth`, SKI and AKI —
the profile Roles Anywhere and an ELBv2 trust store both expect.

### Authenticate

IAM Roles Anywhere — no long-lived credentials:

```bash
aws_signing_helper credential-process \
  --certificate workload.pem --private-key workload.key \
  --trust-anchor-arn "$(terraform output -raw trust_anchor_arn)" \
  --profile-arn "$(terraform output -json profile_arns | python3 -c 'import json,sys;print(list(json.load(sys.stdin).values())[0])')" \
  --role-arn "$(terraform output -json workload_role_arns | python3 -c 'import json,sys;print(list(json.load(sys.stdin).values())[0])')"
```

ALB mutual TLS — point an HTTPS listener at the trust store
(`aws_lb_listener.mutual_authentication { mode = "verify", trust_store_arn = … }`):

```bash
curl --cert workload.pem --key workload.key https://internal.example.com/health
```

### Revoke a certificate

The CRL is generated from a revocation list and re-imported by the consumer's
Lambda; a serial is revoked everywhere that list is read.

```bash
# Roles Anywhere reads s3://<artifacts>/revocations/revoked.json
aws s3 cp "s3://$(terraform output -json ca_contract | python3 -c 'import json,sys;print(json.load(sys.stdin)["artifacts_bucket"])')/revocations/revoked.json" revoked.json
python3 - <<'PY'
import json
data = json.load(open("revoked.json")) if __import__("os").path.exists("revoked.json") else {"revoked": []}
data["revoked"].append({"serial": "0x5f89eca173f0e5", "reason": "key_compromise"})
json.dump(data, open("revoked.json", "w"), indent=2)
PY
aws s3 cp revoked.json "s3://$(terraform output -json ca_contract | python3 -c 'import json,sys;print(json.load(sys.stdin)["artifacts_bucket"])')/revocations/revoked.json"

# import immediately instead of waiting for the 24h tick. Both consumers read
# this one object, so invoke both: a certificate revoked through this procedure
# must be rejected by Roles Anywhere and by the ALB.
aws lambda invoke --function-name "$(terraform output -raw crl_issuer_function_name)" \
  --payload '{"reason":"manual-revocation"}' --cli-binary-format raw-in-base64-out /dev/stdout
aws lambda invoke --function-name "$(terraform output -raw alb_sync_function_name)" \
  --payload '{"reason":"manual-revocation"}' --cli-binary-format raw-in-base64-out /dev/stdout
```

The ALB consumer reads the same S3 object by default. `alb_revoked_serials_ssm_param`
remains as an explicit override for a stack that keeps a separate SSM source; an
unset override means "use S3", and a configured but missing or invalid source
fails closed instead of clearing the installed CRL.

### Rotate the Intermediate CA

```bash
terraform output -raw start_rotation_command | bash   # mode=ROTATE_INTERMEDIATE
```

Rotation restores the Root key from the encrypted cluster backup (a `READY` backup
is required — the workflow refuses to start otherwise), re-signs a new Intermediate
with the same KMS key, publishes the new chain, and the consumers re-activate via
the same event. Five-year default validity: `intermediate_ca_validity_days`.

## Submodules & examples

| Module | Purpose |
|---|---|
| [`modules/hsm-ca`](modules/hsm-ca/README.md) | Core PKI engine: CloudHSM Root CA ceremony, KMS Intermediate key, SSM chain, `CAChainPublished` fan-out |
| [`modules/roles-anywhere`](modules/roles-anywhere/README.md) | IAM Roles Anywhere consumer: trust anchor, profiles, workload roles, CRL import |
| [`modules/alb-mtls`](modules/alb-mtls/README.md) | ALB mutual-TLS consumer: `aws_lb_trust_store` with atomic PEM CRL rotation |

| Example | Shows |
|---|---|
| [`examples/complete`](examples/complete) | Composite module, `auto_bootstrap = false`, both consumers |
| [`examples/auto-bootstrap`](examples/auto-bootstrap) | Composite module with `auto_bootstrap = true` |
| [`examples/standalone-hsm-ca`](examples/standalone-hsm-ca) | The PKI engine alone, for mTLS/VPN/TLS consumers it does not know about |

## Requirements, providers, resources, inputs & outputs

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.4.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.67.0, < 7.0.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.5.0 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | >= 4.0.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.73.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| <a name="module_alb_mtls"></a> [alb\_mtls](#module\_alb\_mtls) | ./modules/alb-mtls | n/a |
| <a name="module_hsm_ca"></a> [hsm\_ca](#module\_hsm\_ca) | ./modules/hsm-ca | n/a |
| <a name="module_roles_anywhere"></a> [roles\_anywhere](#module\_roles\_anywhere) | ./modules/roles-anywhere | n/a |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_alb_mtls_name"></a> [alb\_mtls\_name](#input\_alb\_mtls\_name) | S3 prefix name for the ALB trust store artifacts (alb-mtls/<name>/). Empty = the CA's name. | `string` | `""` | no |
| <a name="input_alb_revoked_serials_ssm_param"></a> [alb\_revoked\_serials\_ssm\_param](#input\_alb\_revoked\_serials\_ssm\_param) | SSM parameter holding revoked serials as JSON for the ALB CRL. Empty = do not rotate the CRL; set to a parameter containing {"revoked": []} to explicitly clear serials. A configured but missing or invalid parameter fails closed. | `string` | `""` | no |
| <a name="input_alb_trust_store_name"></a> [alb\_trust\_store\_name](#input\_alb\_trust\_store\_name) | Explicit ELBv2 trust store name (max 32 chars). Empty = <ca\_name>-alb-mtls. | `string` | `""` | no |
| <a name="input_allowed_kms_signer_role_arns"></a> [allowed\_kms\_signer\_role\_arns](#input\_allowed\_kms\_signer\_role\_arns) | Exact IAM role ARNs besides the ceremony host allowed to sign with the Intermediate key. null = the composite stack's designated CRL issuer role only; workload roles are never implied by a pattern. | `list(string)` | `null` | no |
| <a name="input_artifact_bucket_name"></a> [artifact\_bucket\_name](#input\_artifact\_bucket\_name) | Explicit artifact bucket name. Empty = generated unique name. | `string` | `""` | no |
| <a name="input_audit_log_retention_days"></a> [audit\_log\_retention\_days](#input\_audit\_log\_retention\_days) | Retention for the CloudHSM audit log group /aws/cloudhsm/<cluster-id>. | `number` | `90` | no |
| <a name="input_auto_bootstrap"></a> [auto\_bootstrap](#input\_auto\_bootstrap) | true runs the ceremony inside terraform apply and waits for it; false (default) leaves it to the operator. | `bool` | `false` | no |
| <a name="input_auto_bootstrap_timeout_seconds"></a> [auto\_bootstrap\_timeout\_seconds](#input\_auto\_bootstrap\_timeout\_seconds) | How long the auto\_bootstrap waiter polls before failing the apply. | `number` | `3600` | no |
| <a name="input_availability_zone"></a> [availability\_zone](#input\_availability\_zone) | AZ for the ceremony HSM. Must be an AZ of one of var.private\_subnet\_ids. | `string` | n/a | yes |
| <a name="input_backup_retention_days"></a> [backup\_retention\_days](#input\_backup\_retention\_days) | Days CloudHSM keeps cluster backups. The escrow backup is the only copy of the Root key once the ephemeral HSM is deleted. | `number` | `90` | no |
| <a name="input_ceremony_instance_type"></a> [ceremony\_instance\_type](#input\_ceremony\_instance\_type) | Instance type for the ephemeral ceremony host. | `string` | `"t3.small"` | no |
| <a name="input_cloudhsm_cli_rpm"></a> [cloudhsm\_cli\_rpm](#input\_cloudhsm\_cli\_rpm) | AWS CloudHSM Client SDK 5 CLI package for Amazon Linux 2023. | `string` | `"https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"` | no |
| <a name="input_cloudhsm_cli_rpm_sha256"></a> [cloudhsm\_cli\_rpm\_sha256](#input\_cloudhsm\_cli\_rpm\_sha256) | SHA-256 of the CloudHSM CLI RPM, verified before the ceremony installs it. Required for a bootstrap. | `string` | `""` | no |
| <a name="input_commissioning_ca"></a> [commissioning\_ca](#input\_commissioning\_ca) | The approved CA that claims a new CloudHSM cluster (public certificate plus an SSM SecureString parameter holding the key, or a pre-signed cluster certificate). Required for the first bootstrap of an UNINITIALIZED cluster. | <pre>object({<br/>    certificate                = string<br/>    key_ssm_param              = optional(string, "")<br/>    signed_cluster_certificate = optional(string, "")<br/>  })</pre> | <pre>{<br/>  "certificate": "",<br/>  "key_ssm_param": "",<br/>  "signed_cluster_certificate": ""<br/>}</pre> | no |
| <a name="input_crl_validity_days"></a> [crl\_validity\_days](#input\_crl\_validity\_days) | thisUpdate -> nextUpdate window of every generated CRL. Must exceed the 24h refresh cadence. | `number` | `7` | no |
| <a name="input_enable_alb_mtls"></a> [enable\_alb\_mtls](#input\_enable\_alb\_mtls) | Create the ALB mutual-TLS consumer (ELBv2 trust store + activation/CRL Lambda). false = no trust store. | `bool` | `false` | no |
| <a name="input_enable_bootstrap"></a> [enable\_bootstrap](#input\_enable\_bootstrap) | true for a first-time cluster (publishes the bootstrap entrypoint and admin password); false for rotation-only. | `bool` | `true` | no |
| <a name="input_enable_roles_anywhere"></a> [enable\_roles\_anywhere](#input\_enable\_roles\_anywhere) | Create the IAM Roles Anywhere consumer (trust anchor, profiles, workload roles, CRL Lambda). false = PKI engine only. | `bool` | `true` | no |
| <a name="input_escrow_wait_minutes"></a> [escrow\_wait\_minutes](#input\_escrow\_wait\_minutes) | Minutes the workflow waits for the deletion-triggered escrow backup to reach READY; polled every 60 seconds, so this is the maximum number of polls. | `number` | `60` | no |
| <a name="input_event_bus_name"></a> [event\_bus\_name](#input\_event\_bus\_name) | EventBridge bus for CAChainPublished. Consumers must subscribe to the same bus. | `string` | `"default"` | no |
| <a name="input_hsm_crypto_user"></a> [hsm\_crypto\_user](#input\_hsm\_crypto\_user) | CloudHSM crypto user that owns the Root key. Letters, digits and underscore only, per CloudHSM. | `string` | `"pki_cu"` | no |
| <a name="input_intermediate_ca_validity_days"></a> [intermediate\_ca\_validity\_days](#input\_intermediate\_ca\_validity\_days) | Intermediate CA lifetime (bootstrap and rotation). | `number` | `1825` | no |
| <a name="input_intermediate_key_spec"></a> [intermediate\_key\_spec](#input\_intermediate\_key\_spec) | Key spec of the KMS Intermediate CA key. | `string` | `"ECC_NIST_P384"` | no |
| <a name="input_intermediate_subject"></a> [intermediate\_subject](#input\_intermediate\_subject) | Distinguished name of the KMS-backed Intermediate CA. | <pre>object({<br/>    country             = optional(string, "US")<br/>    state               = optional(string, "Washington")<br/>    locality            = optional(string, "Seattle")<br/>    organization        = optional(string, "Example Corp")<br/>    organizational_unit = optional(string, "Platform Security")<br/>    common_name         = optional(string, "Example Corp Issuing CA")<br/>  })</pre> | `{}` | no |
| <a name="input_kms_deletion_window_in_days"></a> [kms\_deletion\_window\_in\_days](#input\_kms\_deletion\_window\_in\_days) | Waiting period before the Intermediate CA key can be destroyed. | `number` | `30` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | Retention for every log group this stack creates. | `number` | `365` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for every resource, SSM path and IAM role name. Consumers match the CAChainPublished event on this value. | `string` | `"corp-pki"` | no |
| <a name="input_object_lock_days"></a> [object\_lock\_days](#input\_object\_lock\_days) | S3 Object Lock default retention period in days. | `number` | `30` | no |
| <a name="input_object_lock_mode"></a> [object\_lock\_mode](#input\_object\_lock\_mode) | S3 Object Lock default retention mode. | `string` | `"GOVERNANCE"` | no |
| <a name="input_permissions_boundary_arn"></a> [permissions\_boundary\_arn](#input\_permissions\_boundary\_arn) | Optional IAM permissions boundary ARN attached to every role this module creates. Null leaves roles unbounded. | `string` | `null` | no |
| <a name="input_private_subnet_ids"></a> [private\_subnet\_ids](#input\_private\_subnet\_ids) | Private subnets for the CloudHSM cluster. The ceremony host is launched in the first one. | `list(string)` | n/a | yes |
| <a name="input_revocations_s3_key"></a> [revocations\_s3\_key](#input\_revocations\_s3\_key) | S3 key inside the CA artifact bucket holding the revoked-serial JSON read by the CRL Lambda. | `string` | `"revocations/revoked.json"` | no |
| <a name="input_root_ca_validity_days"></a> [root\_ca\_validity\_days](#input\_root\_ca\_validity\_days) | Root CA lifetime (bootstrap only). | `number` | `3650` | no |
| <a name="input_root_key_curve"></a> [root\_key\_curve](#input\_root\_key\_curve) | CloudHSM curve for the non-exportable Root CA key. | `string` | `"secp384r1"` | no |
| <a name="input_root_subject"></a> [root\_subject](#input\_root\_subject) | Distinguished name of the offline Root CA. | <pre>object({<br/>    country             = optional(string, "US")<br/>    state               = optional(string, "Washington")<br/>    locality            = optional(string, "Seattle")<br/>    organization        = optional(string, "Example Corp")<br/>    organizational_unit = optional(string, "Platform Security")<br/>    common_name         = optional(string, "Example Corp Root CA")<br/>  })</pre> | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to every taggable resource. Module = "cloudhsmca" is always added. | `map(string)` | `{}` | no |
| <a name="input_uv_installer_sha256"></a> [uv\_installer\_sha256](#input\_uv\_installer\_sha256) | Optional SHA-256 of the uv install script. | `string` | `""` | no |
| <a name="input_uv_version"></a> [uv\_version](#input\_uv\_version) | Exact uv release the ceremony installs. | `string` | `"0.5.11"` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC containing the private subnets for the CloudHSM cluster and the ceremony host. | `string` | n/a | yes |
| <a name="input_workload_profiles"></a> [workload\_profiles](#input\_workload\_profiles) | One Roles Anywhere profile + IAM role per workload class, keyed by a short stable name. | <pre>map(object({<br/>    description              = optional(string, "Managed by cloudhsmca")<br/>    session_duration_seconds = optional(number, 3600)<br/>    # IAM role ceiling: leave null to floor at 3600 automatically.<br/>    role_max_session_duration  = optional(number)<br/>    managed_policy_arns        = optional(list(string), [])<br/>    session_policy_json        = optional(string)<br/>    accept_role_session_name   = optional(bool, true)<br/>    subject_condition_operator = optional(string, "StringEquals")<br/>    allowed_subject_ou         = optional(string)<br/>    allowed_subject_cn         = optional(string)<br/>    tags                       = optional(map(string), {})<br/>  }))</pre> | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_alb_sync_function_name"></a> [alb\_sync\_function\_name](#output\_alb\_sync\_function\_name) | ALB trust-store activation + CRL rotation Lambda (null when disabled). |
| <a name="output_alb_trust_store_arn"></a> [alb\_trust\_store\_arn](#output\_alb\_trust\_store\_arn) | ELBv2 trust store ARN for aws\_lb\_listener.mutual\_authentication (null when enable\_alb\_mtls = false). |
| <a name="output_alb_trust_store_name"></a> [alb\_trust\_store\_name](#output\_alb\_trust\_store\_name) | ELBv2 trust store name (null when disabled). |
| <a name="output_artifact_bucket"></a> [artifact\_bucket](#output\_artifact\_bucket) | Bucket holding the tooling, issued certificates, CRLs and revocation input. |
| <a name="output_ca_contract"></a> [ca\_contract](#output\_ca\_contract) | The workload-agnostic contract: key and bucket ARNs, SSM parameter names, signing algorithm, event bus/source/detail-type. |
| <a name="output_certificate_parameters"></a> [certificate\_parameters](#output\_certificate\_parameters) | SSM Parameter Store paths the ceremony publishes and biometric consumers read. |
| <a name="output_cloudhsm_backup_guard_policy_arn"></a> [cloudhsm\_backup\_guard\_policy\_arn](#output\_cloudhsm\_backup\_guard\_policy\_arn) | Attach this policy to every principal that can manage CloudHSM (it denies backup deletion). |
| <a name="output_cloudhsm_cluster_id"></a> [cloudhsm\_cluster\_id](#output\_cloudhsm\_cluster\_id) | Durable cluster shell. Its backups escrow the Root CA key. |
| <a name="output_crl_issuer_function_name"></a> [crl\_issuer\_function\_name](#output\_crl\_issuer\_function\_name) | Activation + CRL refresh Lambda (null when disabled). |
| <a name="output_intermediate_kms_key_arn"></a> [intermediate\_kms\_key\_arn](#output\_intermediate\_kms\_key\_arn) | The KMS Intermediate CA key: signs workload certificates and CRLs, never exportable. |
| <a name="output_profile_arns"></a> [profile\_arns](#output\_profile\_arns) | Map of workload key -> Roles Anywhere profile ARN (empty when disabled). |
| <a name="output_rolesanywhere_update_env"></a> [rolesanywhere\_update\_env](#output\_rolesanywhere\_update\_env) | Values for aws\_signing\_helper (null when disabled). |
| <a name="output_start_bootstrap_command"></a> [start\_bootstrap\_command](#output\_start\_bootstrap\_command) | Start a bootstrap ceremony (the cluster must be UNINITIALIZED). Prints the execution ARN. |
| <a name="output_start_rotation_command"></a> [start\_rotation\_command](#output\_start\_rotation\_command) | Start an intermediate rotation (needs a READY cluster backup). Prints the execution ARN. |
| <a name="output_state_machine_arn"></a> [state\_machine\_arn](#output\_state\_machine\_arn) | Run the ceremony with `aws stepfunctions start-execution`. |
| <a name="output_trust_anchor_arn"></a> [trust\_anchor\_arn](#output\_trust\_anchor\_arn) | IAM Roles Anywhere trust anchor (null when enable\_roles\_anywhere = false). Created DISABLED; the ceremony's event activates it. |
| <a name="output_trust_anchor_id"></a> [trust\_anchor\_id](#output\_trust\_anchor\_id) | Trust anchor id (null when enable\_roles\_anywhere = false). |
| <a name="output_workload_role_arns"></a> [workload\_role\_arns](#output\_workload\_role\_arns) | Map of workload key -> IAM role ARN assumable through Roles Anywhere (empty when disabled). |
<!-- END_TF_DOCS -->

## Testing & verification

```bash
make init        # one init per configuration, into one shared provider cache
make -j4 check   # fmt, validate, tflint, workflow lint and seven offline harnesses (~40 s)
```

The offline harnesses need no AWS account: they exercise the X.509 chain, the
ceremony script against a stub CloudHSM CLI that really signs, the rendered state
machine as a graph, and both consumer Lambdas extracted from their Terraform
heredocs. The live-only unknowns are covered separately by
`scripts/verify_live_control_plane.sh` — a **$0**, no-HSM script that builds a
chain with the deployed KMS key, emits a synthetic `CAChainPublished`, and asserts
the trust anchor and CRL come up. What is verified offline versus in a live
account, and how, is in [`tests/README.md`](tests/README.md).

Apache-2.0 — see [LICENSE](LICENSE).
