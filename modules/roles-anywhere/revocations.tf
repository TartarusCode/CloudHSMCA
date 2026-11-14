# The revocation list the CRL Lambda reads.
#
# Nothing in this module revokes anything on its own, so without a seeded object
# the first CRL import fails: the Lambda's GetObject hits a missing key, S3 answers
# AccessDenied (not NoSuchKey) because the role has no s3:ListBucket, and the
# handler dies before importing. That is how it behaved in the first live run.
#
# ignore_changes on content: operators edit this object to revoke a serial, and a
# later apply must not put the empty list back.
resource "aws_s3_object" "revocations" {
  bucket       = var.ca_contract.artifacts_bucket
  key          = var.revocations_s3_key
  content      = jsonencode({ revoked = [] })
  content_type = "application/json"

  lifecycle {
    ignore_changes = [content, etag]
  }
}
