# hsm-ca

The PKI engine: a CloudHSM-backed Root CA whose key never exists in a file, an
always-online KMS Intermediate CA, and one Step Functions workflow that performs
the ceremony and publishes the resulting chain. It knows nothing about who
consumes the certificates.

```hcl
module "hsm_ca" {
  source = "git::https://github.com/TartarusCode/CloudHSMCA.git//modules/hsm-ca?ref=main"

  name               = "corp-pki"
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0123456789abcdef0"]
  availability_zone  = "us-east-1a"
}
```

## What an apply creates

No HSM, and no certificate. An apply creates the durable **cluster shell** (the
thing whose backups escrow the Root key), the KMS **Intermediate** key and its
alias, the artifact bucket, three SSM parameters holding `PENDING-CEREMONY`, the
ceremony host's IAM role, the Step Functions state machine and its logs, and the
`PublishCaReady` permission the workflow needs to emit its event.

The ceremony is what creates a `hsm2m.medium` in FIPS mode, generates the Root key
with `EXTRACTABLE=false`, self-signs the Root CA, signs the Intermediate's CSR
inside the HSM, verifies the encrypted cluster backup reaches `READY`, then deletes
the HSM and terminates the host. Until it succeeds there is no certificate and no
hourly HSM charge.

```bash
terraform output -raw start_bootstrap_command | bash   # mode=BOOTSTRAP
terraform output -raw start_rotation_command  | bash   # mode=ROTATE_INTERMEDIATE
```

Both accept an explicit mode; omit it and the workflow infers it from whether the
cluster is already initialized. `ROTATE_INTERMEDIATE` restores the Root key from the
backup, re-signs only the Intermediate, and refuses to start if no backup is `READY`.

## The contract

`ca_contract` is the module's only interface, and it is deliberately boring:

| field | use |
|---|---|
| `intermediate_kms_key_arn`, `intermediate_kms_key_alias`, `signing_algorithm`, `intermediate_key_spec` | sign leaves and CRLs |
| `root_ca_ssm_param`, `intermediate_ca_ssm_param`, `ca_bundle_ssm_param`, `ceremony_state_ssm_param` | read the published chain and ceremony state |
| `artifacts_bucket`, `artifacts_bucket_arn` | write CRL and revocation artifacts |
| `event_bus_name`, `event_source`, `event_detail_type` | subscribe to `CAChainPublished` |
| `name`, `region`, `account_id`, `partition`, `cluster_id` | name things deterministically |

Consumers never reference a resource in this module, and this module references no
consumer, so the engine and any consumer can be applied in either order.

## KMS key policy

The Intermediate key accepts signatures only from exact `aws:PrincipalArn` values in
`allowed_kms_signer_role_arns` (plus the ceremony host). Wildcards are rejected by
variable validation: a workload role named `<ca_name>-…` must never enter the CA
key's authorization boundary. The composite stack passes its designated CRL issuer
ARN; a caller with separate consumers passes their exact ARNs. Signing still
requires `kms:MessageType = DIGEST` plus the key's own signing algorithm.

The administration statement uses the account root principal and enumerates the 17
non-cryptographic lifecycle actions. It grants neither `kms:Sign` nor
`kms:CreateGrant`: either would let an administrator sidestep those conditions.

Principal ARNs are never written into `Principal.AWS`. KMS rejects a policy that
names a role which does not exist yet, and rewrites an existing role principal to an
`AROA…` id, which would churn on every plan.

## Design tradeoffs

Two choices are deliberate, and both trade a safety property against cost and
operability. Neither is hidden behind a default.

**Ephemeral single-HSM ceremony + `READY` backup escrow, instead of 2–3 always-on
HSMs.** CloudHSM key availability quorum requires a key to exist on at least two
HSMs, so a one-HSM cluster needs `configure-cli --disable-key-availability-check`
(the ceremony does this only when the cluster really has fewer than two HSMs). The
Root key lives in a single HSM for the duration of the ceremony, and afterwards
only in the encrypted cluster backup. That is cheaper by roughly two orders of
magnitude (a ceremony hour instead of a 24×7 cluster), but it means: (a) a
hardware failure during the ceremony loses that run's key, (b) the module cannot
report success until a backup is `READY`, and AWS creates backups on cluster
activation and HSM add/remove rather than on demand — there is no `CreateBackup`
API — so the wait is bounded by `escrow_wait_minutes` (default 180) and fails
closed on timeout. A cluster that must tolerate an HSM loss should run two or three
HSMs and leave the quorum check enabled.

**Unattended Step Functions automation instead of M-of-N quorum authentication.**
The ceremony runs as one state machine with one execution role and generated
passwords in Secrets Manager, so it can be triggered by CI with no human in the
loop. CloudHSM's own alternative is quorum authentication: several crypto officers
each approve a signing operation. That defends against a single compromised
operator, which this module does not. The compensations here are narrower: the Root
key is non-extractable (`extractable=false`, verified before any certificate is
issued), the KMS Intermediate key policy allows only exact principal ARNs, every
ceremony is one auditable execution with a CloudWatch audit log
(`/aws/cloudhsm/<cluster-id>`, retention `audit_log_retention_days`), and the
cluster backup window is explicit (`backup_retention_days`). An organisation that
needs operator separation should treat the state machine as the *transport* and add
quorum approval inside the ceremony script.

## Cost

$0/hr at steady state — the HSM exists only during a ceremony (about $1.50/hr) and
its encrypted backups are retained at no charge. The KMS asymmetric key is about
$1/month.

## Testing

```bash
make test    # tests/module (locals as plan computes them), tests/crypto (the X.509
             # tool), tests/ceremony (the script against a stub HSM CLI that signs),
             # tests/asl_invariants.py (the state machine as a graph)
```

`tests/asl_invariants.py` fails the build if the workflow grows a consumer-specific
state, if a failure path skips the HSM cleanup, or if a list parameter carries a
literal `$.` reference instead of `States.Array`.

---

*Input and output tables generated by [terraform-docs](https://terraform-docs.io) — `make docs`.*

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.67.0, < 7.0.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.5.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.73.0 |
| <a name="provider_random"></a> [random](#provider\_random) | 3.9.1 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_cloudhsm_v2_cluster.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudhsm_v2_cluster) | resource |
| [aws_cloudwatch_log_group.ceremony](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.cluster_audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_dynamodb_table.ceremony_lease](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |
| [aws_iam_instance_profile.ceremony_host](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_policy.cloudhsm_backup_guard](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.ceremony_host](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.sfn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.ceremony_host](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sfn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.ceremony_ssm_core](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.cloudhsm_backup_guard](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.intermediate_ca](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.intermediate_ca](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_object_lock_configuration.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration) | resource |
| [aws_s3_bucket_policy.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.artifacts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_s3_object.bootstrap_entrypoint](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.bootstrap_script](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.intermediate_ca_cnf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.kms_ca_tool](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.root_ca_cnf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.rotate_script](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_secretsmanager_secret.hsm_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret.hsm_cu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret_version.hsm_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version) | resource |
| [aws_secretsmanager_secret_version.hsm_cu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version) | resource |
| [aws_security_group.ceremony](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group_rule.cluster_from_ceremony](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_sfn_state_machine.ceremony](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sfn_state_machine) | resource |
| [aws_ssm_parameter.ca_bundle_pem](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.ceremony_state](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.intermediate_ca_pem](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.root_ca_pem](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_ssm_parameter.verified_backup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [random_password.hsm_admin](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.hsm_cu](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [terraform_data.auto_bootstrap](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [terraform_data.backup_retention](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [aws_ami.al2023](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.artifacts_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.ceremony_host](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudhsm_backup_guard](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.ec2_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.intermediate_ca_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sfn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sfn_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_kms_alias.ssm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_alias) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_allowed_kms_signer_role_arns"></a> [allowed\_kms\_signer\_role\_arns](#input\_allowed\_kms\_signer\_role\_arns) | IAM role ARNs, besides the ceremony host, allowed to use the Intermediate CA<br/>key for signing: kms:Sign under the digest-only conditions, plus<br/>GetPublicKey/DescribeKey. This is how a consumer module signs CRLs or leaf<br/>certificates without the core module having to know it exists — no circular<br/>key policy, no cross-stack resource reference.<br/><br/>An empty list is the safe default: only the ceremony host can sign. Pass the<br/>exact ARNs of designated signing services (for example the CRL issuer) to<br/>grant them access. Wildcards are rejected because a workload role that<br/>matches the pattern would otherwise enter the CA key's authorization<br/>boundary; the digest-only conditions cannot distinguish a CRL from a<br/>certificate signature. | `list(string)` | `[]` | no |
| <a name="input_artifact_bucket_name"></a> [artifact\_bucket\_name](#input\_artifact\_bucket\_name) | Explicit bucket name for the ceremony tooling, issued certificates, CRLs and audit copies. Empty = generated unique name. | `string` | `""` | no |
| <a name="input_audit_log_retention_days"></a> [audit\_log\_retention\_days](#input\_audit\_log\_retention\_days) | Retention for the CloudHSM audit log group /aws/cloudhsm/<cluster-id>. | `number` | `90` | no |
| <a name="input_auto_bootstrap"></a> [auto\_bootstrap](#input\_auto\_bootstrap) | false (default) — `terraform apply` lands in under a minute and the operator<br/>  starts the ceremony out of band:<br/>  `terraform output -raw start_bootstrap_command | bash`.<br/><br/>true — apply runs the ceremony itself (a terraform\_data local-exec that<br/>  starts the execution and polls until SUCCEEDED). The ceremony takes ~15-45<br/>  minutes and needs the AWS CLI on the machine running apply. | `bool` | `false` | no |
| <a name="input_auto_bootstrap_timeout_seconds"></a> [auto\_bootstrap\_timeout\_seconds](#input\_auto\_bootstrap\_timeout\_seconds) | How long the auto\_bootstrap waiter polls the execution before failing the apply. | `number` | `3600` | no |
| <a name="input_availability_zone"></a> [availability\_zone](#input\_availability\_zone) | AZ for the ceremony HSM. Must be an AZ of one of var.private\_subnet\_ids. | `string` | n/a | yes |
| <a name="input_backup_retention_days"></a> [backup\_retention\_days](#input\_backup\_retention\_days) | Days CloudHSM keeps cluster backups. The escrow backup holds the only copy of the Root key after the ephemeral HSM is deleted. | `number` | `90` | no |
| <a name="input_ceremony_instance_type"></a> [ceremony\_instance\_type](#input\_ceremony\_instance\_type) | Instance type for the ephemeral ceremony host. Nano and micro sizes are rejected: the ceremony builds a venv, installs the CloudHSM CLI and runs OpenSSL, which those shapes cannot do reliably. | `string` | `"t3.small"` | no |
| <a name="input_cloudhsm_cli_rpm"></a> [cloudhsm\_cli\_rpm](#input\_cloudhsm\_cli\_rpm) | AWS CloudHSM Client SDK 5 CLI package for Amazon Linux 2023. | `string` | `"https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm"` | no |
| <a name="input_cloudhsm_cli_rpm_sha256"></a> [cloudhsm\_cli\_rpm\_sha256](#input\_cloudhsm\_cli\_rpm\_sha256) | SHA-256 of the CloudHSM CLI RPM. Required: the ceremony verifies the download before installing a package that can reach the root key. | `string` | `""` | no |
| <a name="input_commissioning_ca"></a> [commissioning\_ca](#input\_commissioning\_ca) | The separate, approved CA that claims a NEW CloudHSM cluster. Terraform<br/>creates clusters UNINITIALIZED; the ceremony must sign the cluster CSR and<br/>call InitializeCluster before it can activate the cluster. The private key<br/>never enters Terraform state: supply either an SSM SecureString parameter<br/>name holding it, or a pre-signed cluster certificate (fully offline mode).<br/>The certificate is public and is installed as the client's trust anchor. | <pre>object({<br/>    certificate                = string<br/>    key_ssm_param              = optional(string, "")<br/>    signed_cluster_certificate = optional(string, "")<br/>  })</pre> | <pre>{<br/>  "certificate": "",<br/>  "key_ssm_param": "",<br/>  "signed_cluster_certificate": ""<br/>}</pre> | no |
| <a name="input_enable_bootstrap"></a> [enable\_bootstrap](#input\_enable\_bootstrap) | true  — this cluster has never been initialized, so publish the bootstrap<br/>        entrypoint, the admin password and the Root CA inputs.<br/>false — rotation only: the Root key is restored from the cluster backup, and<br/>        the admin password is not needed.<br/>Both entrypoints are always safe to publish; this flag only hides the ones a<br/>rotation must never use. | `bool` | `true` | no |
| <a name="input_escrow_wait_minutes"></a> [escrow\_wait\_minutes](#input\_escrow\_wait\_minutes) | How long the workflow waits for the service-scheduled escrow backup to reach READY after the HSM is deleted. AWS CloudHSM has no API to force a backup; it is created on cluster activation, HSM add and HSM removal, and can take a while. | `number` | `180` | no |
| <a name="input_event_bus_name"></a> [event\_bus\_name](#input\_event\_bus\_name) | EventBridge bus the CAChainPublished event is emitted on. Consumers must subscribe to the same bus. | `string` | `"default"` | no |
| <a name="input_hsm_crypto_user"></a> [hsm\_crypto\_user](#input\_hsm\_crypto\_user) | CloudHSM crypto user that owns the Root key. It survives in the backup, so rotation re-uses it. CloudHSM allows only letters, digits and underscore. | `string` | `"pki_cu"` | no |
| <a name="input_intermediate_ca_validity_days"></a> [intermediate\_ca\_validity\_days](#input\_intermediate\_ca\_validity\_days) | Intermediate CA lifetime. Used by both bootstrap and rotation. | `number` | `1825` | no |
| <a name="input_intermediate_key_spec"></a> [intermediate\_key\_spec](#input\_intermediate\_key\_spec) | Key spec of the Intermediate CA key, which this module creates. Also drives the digest in the OpenSSL profiles. | `string` | `"ECC_NIST_P384"` | no |
| <a name="input_intermediate_subject"></a> [intermediate\_subject](#input\_intermediate\_subject) | Distinguished name of the KMS-backed Intermediate CA. | <pre>object({<br/>    country             = optional(string, "US")<br/>    state               = optional(string, "Washington")<br/>    locality            = optional(string, "Seattle")<br/>    organization        = optional(string, "Example Corp")<br/>    organizational_unit = optional(string, "Platform Security")<br/>    common_name         = optional(string, "Example Corp Issuing CA")<br/>  })</pre> | `{}` | no |
| <a name="input_kms_deletion_window_in_days"></a> [kms\_deletion\_window\_in\_days](#input\_kms\_deletion\_window\_in\_days) | Waiting period before the Intermediate CA key can be destroyed. | `number` | `30` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | Retention for the state machine, ceremony host and consumer log groups. | `number` | `365` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for every resource, SSM path and IAM role name. Consumers match the event on this value. | `string` | `"corp-pki"` | no |
| <a name="input_object_lock_days"></a> [object\_lock\_days](#input\_object\_lock\_days) | S3 Object Lock default retention period in days. | `number` | `30` | no |
| <a name="input_object_lock_mode"></a> [object\_lock\_mode](#input\_object\_lock\_mode) | S3 Object Lock default retention mode. COMPLIANCE is recommended for CRL artifacts and cannot be shortened. | `string` | `"GOVERNANCE"` | no |
| <a name="input_permissions_boundary_arn"></a> [permissions\_boundary\_arn](#input\_permissions\_boundary\_arn) | Optional IAM permissions boundary ARN attached to every role this module creates. Null leaves roles unbounded. | `string` | `null` | no |
| <a name="input_private_subnet_ids"></a> [private\_subnet\_ids](#input\_private\_subnet\_ids) | Private subnets for the CloudHSM cluster. The ceremony host is launched in the first one. | `list(string)` | n/a | yes |
| <a name="input_root_ca_validity_days"></a> [root\_ca\_validity\_days](#input\_root\_ca\_validity\_days) | Root CA lifetime. Only used by the bootstrap ceremony. | `number` | `3650` | no |
| <a name="input_root_key_curve"></a> [root\_key\_curve](#input\_root\_key\_curve) | CloudHSM curve for the non-exportable Root CA key. | `string` | `"secp384r1"` | no |
| <a name="input_root_subject"></a> [root\_subject](#input\_root\_subject) | Distinguished name of the offline Root CA. | <pre>object({<br/>    country             = optional(string, "US")<br/>    state               = optional(string, "Washington")<br/>    locality            = optional(string, "Seattle")<br/>    organization        = optional(string, "Example Corp")<br/>    organizational_unit = optional(string, "Platform Security")<br/>    common_name         = optional(string, "Example Corp Root CA")<br/>  })</pre> | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to every taggable resource. `Module = "cloudhsmca"` is always added. | `map(string)` | `{}` | no |
| <a name="input_uv_installer_sha256"></a> [uv\_installer\_sha256](#input\_uv\_installer\_sha256) | Optional SHA-256 of the uv install script. Strongly recommended; without it the installer is pinned only by uv\_version. | `string` | `""` | no |
| <a name="input_uv_version"></a> [uv\_version](#input\_uv\_version) | Exact uv release the ceremony installs. | `string` | `"0.5.11"` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC containing the private subnets for the cluster ENIs and the ephemeral ceremony host. | `string` | n/a | yes |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_ca_contract"></a> [ca\_contract](#output\_ca\_contract) | Everything downstream consumers need: key and bucket ARNs, SSM parameter names, signing algorithm, and the CAChainPublished event contract. |
| <a name="output_cloudhsm_backup_guard_policy_arn"></a> [cloudhsm\_backup\_guard\_policy\_arn](#output\_cloudhsm\_backup\_guard\_policy\_arn) | Attach this policy to every principal, beyond the two here, that can manage CloudHSM (it denies backup deletion). |
| <a name="output_cloudhsm_cluster_id"></a> [cloudhsm\_cluster\_id](#output\_cloudhsm\_cluster\_id) | Durable cluster shell. Its backups escrow the Root CA key. |
| <a name="output_execution_history_log_group"></a> [execution\_history\_log\_group](#output\_execution\_history\_log\_group) | Every ceremony execution is logged here, with full execution data. |
| <a name="output_start_bootstrap_command"></a> [start\_bootstrap\_command](#output\_start\_bootstrap\_command) | Start a bootstrap ceremony (the cluster must be UNINITIALIZED). Prints the execution ARN. |
| <a name="output_start_rotation_command"></a> [start\_rotation\_command](#output\_start\_rotation\_command) | Start an Intermediate CA rotation (needs a READY cluster backup). |
| <a name="output_state_machine_arn"></a> [state\_machine\_arn](#output\_state\_machine\_arn) | Run the ceremony with `aws stepfunctions start-execution`. |
<!-- END_TF_DOCS -->
