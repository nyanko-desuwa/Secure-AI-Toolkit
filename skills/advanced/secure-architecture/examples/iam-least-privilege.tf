// Least privilege for a service identity.
// Paired discussion: examples/README.md#a-role-that-grants-more-than-the-job-needs
// OWASP A01:2025 / A02:2025 · ASVS V8, V13 · CWE-1220, CWE-250
//
// Placeholders: account 123456789012, bucket acme-invoices-prod, region eu-west-1.
// Read this, then write your own against real resource names. Do not apply as-is.

// ---------------------------------------------------------------------------
// Vulnerable: one role, wildcards on action and resource, no conditions.
// ---------------------------------------------------------------------------
// The invoice renderer needs to read one prefix of one bucket and decrypt with
// one key. This grants every S3 and KMS operation on every resource in the
// account, so a single SSRF or RCE in the renderer becomes account-wide data
// access plus the ability to delete the audit trail.

resource "aws_iam_role_policy" "renderer_vulnerable" {
  name = "renderer-vulnerable"
  role = aws_iam_role.renderer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "kms:*"]
      Resource = "*"
    }]
  })
}

// Compounding problem: the trust policy lets any principal in the account
// assume the role, so any compromised workload inherits it.

resource "aws_iam_role" "renderer_vulnerable_trust" {
  name = "invoice-renderer-vulnerable"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

// ---------------------------------------------------------------------------
// Fixed: scoped to the operations, the prefix, and the one caller.
// ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  bucket_name = "acme-invoices-prod"
  // The renderer only ever touches rendered output under this prefix.
  prefix = "rendered/"
}

// Trust policy: only this specific Kubernetes service account, via OIDC.
// No long-lived access key exists for this identity.
resource "aws_iam_role" "renderer" {
  name                 = "invoice-renderer"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${local.account_id}:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEOIDCID"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          // Subject pins namespace AND service account name. Without this the
          // condition matches any pod in the cluster.
          "oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEOIDCID:sub" = "system:serviceaccount:billing:invoice-renderer"
          "oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEOIDCID:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

data "aws_iam_policy_document" "renderer" {
  // Read the source objects. GetObject only: no List, no Delete, no Put.
  statement {
    sid       = "ReadRenderedInvoices"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.bucket_name}/${local.prefix}*"]
  }

  // Write output to a separate prefix it cannot read back.
  statement {
    sid       = "WriteRenderedOutput"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${local.bucket_name}/output/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  // Decrypt with one key, and only when the request comes through S3.
  // Without the ViaService condition this key can be used directly to decrypt
  // any ciphertext the caller obtained by some other route.
  statement {
    sid       = "DecryptInvoiceObjects"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.invoices.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.eu-west-1.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "renderer" {
  name   = "invoice-renderer"
  role   = aws_iam_role.renderer.id
  policy = data.aws_iam_policy_document.renderer.json
}

resource "aws_kms_key" "invoices" {
  description             = "Invoice object encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

// Bucket-side backstop. The identity policy above is the primary control; this
// resource policy means a second over-broad identity policy elsewhere in the
// account still cannot reach the bucket over plaintext HTTP.
resource "aws_s3_bucket_policy" "invoices" {
  bucket = local.bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnencryptedTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        "arn:aws:s3:::${local.bucket_name}",
        "arn:aws:s3:::${local.bucket_name}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

// ---------------------------------------------------------------------------
// Why the fix holds
// ---------------------------------------------------------------------------
// Blast radius is now the rendered/ prefix of one bucket, read-only, plus write
// to a prefix the same identity cannot read. Compromising the renderer no longer
// reaches other buckets, other keys, or the audit log.
//
// The OIDC trust policy replaces a long-lived access key with a token minted per
// pod, so there is no credential to steal from an environment variable or a
// leaked image layer.
//
// What this does NOT cover, stated plainly:
//   - An attacker inside the pod can still read everything under rendered/. Least
//     privilege bounds the damage; it does not prevent it.
//   - A second role in the account with s3:* still exists unless you audit for it.
//     Scoping one role is not an account-level guarantee. Use an SCP or a
//     permissions boundary if you need that.
//   - The ViaService condition assumes the key is only used through S3. If a
//     future feature calls kms:Decrypt directly, this breaks loudly — which is
//     the intended behaviour, but somebody will be tempted to widen the condition
//     instead of asking why.
