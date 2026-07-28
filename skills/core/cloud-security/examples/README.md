# Cloud Security Examples

These examples show the insecure shape and the defensive shape of common cloud controls. Provider
resource names and identifiers are placeholders; adapt them to the account, subscription, or
project under review. Apply the `Fixed:` configuration only after validating the required data
flows and identities.

## 1. Public object-storage bucket

**References:** OWASP Top 10 2025 A01 (Broken Access Control), A02 (Security Misconfiguration);
OWASP ASVS 5.0 V13 (Configuration), V14 (Data Protection); CWE-732 (Incorrect Permission
Assignment for Critical Resource).

**Vulnerable:** Anonymous principals can read every object in the bucket.

```hcl
resource "aws_s3_bucket_policy" "uploads_vulnerable" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })
}
```

**Fixed:** Block public access, disable ACL-based grants, and require encryption by default.

```hcl
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
  }
}
```

Remove the public allow policy. For Azure, disable anonymous blob access; for GCP, enable public
access prevention and uniform bucket-level access.

## 2. Wildcard IAM permissions

**References:** OWASP Top 10 2025 A01 (Broken Access Control); OWASP ASVS 5.0 V8 (Authorization),
V13 (Configuration); CWE-269 (Improper Privilege Management).

**Vulnerable:** A workload can administer every service and resource in the account.

```hcl
data "aws_iam_policy_document" "worker_vulnerable" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
```

**Fixed:** Grant only the actions and resource prefix required by the workload.

```hcl
data "aws_iam_policy_document" "worker_fixed" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::example-private-bucket",
      "arn:aws:s3:::example-private-bucket/exports/*"
    ]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["exports/*"]
    }
  }
}
```

Constrain `iam:PassRole`, role trust, and permission boundaries separately. Use equivalent custom
roles and deny policies in Azure or GCP rather than broad administrator roles.

## 3. Instance metadata and SSRF

**References:** OWASP Top 10 2025 A01 (Broken Access Control), A02 (Security Misconfiguration),
A06 (Insecure Design); OWASP ASVS 5.0 V2 (Authentication), V13 (Configuration); CWE-918 (Server-
Side Request Forgery).

**Vulnerable:** Optional metadata tokens and a multi-hop response allow an application URL fetcher
to reach instance metadata.

```hcl
resource "aws_instance" "api_vulnerable" {
  ami           = "ami-placeholder"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}
```

**Fixed:** Require IMDSv2, use a one-hop response, and validate outbound URLs in application code.

```hcl
resource "aws_instance" "api_fixed" {
  ami           = "ami-placeholder"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```

The URL client must allowlist schemes and hosts, reject resolved private and link-local ranges,
disable redirects, and enforce timeouts. Azure and GCP metadata-specific headers are defense in
depth, not a replacement for URL validation.

## 4. Overly open security group

**References:** OWASP Top 10 2025 A02 (Security Misconfiguration), A06 (Insecure Design);
OWASP ASVS 5.0 V13 (Configuration); CWE-284 (Improper Access Control), CWE-668 (Exposure of
Resource to Wrong Sphere).

**Vulnerable:** SSH is exposed to the internet and all outbound protocols are permitted.

```hcl
resource "aws_security_group_rule" "app_vulnerable_ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.app.id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "app_vulnerable_egress" {
  type              = "egress"
  security_group_id = aws_security_group.app.id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}
```

**Fixed:** Accept application traffic only from the load balancer and send HTTPS through a named
private proxy or endpoint.

```hcl
resource "aws_security_group_rule" "app_fixed_ingress" {
  type                     = "ingress"
  security_group_id        = aws_security_group.app.id
  protocol                 = "tcp"
  from_port                = 8080
  to_port                  = 8080
  source_security_group_id = aws_security_group.load_balancer.id
}

resource "aws_security_group_rule" "app_fixed_egress" {
  type              = "egress"
  security_group_id = aws_security_group.app.id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["10.20.0.10/32"]
}
```

Use a managed access path for administration instead of public SSH. Match Azure NSG or GCP
firewall rules to the same source, destination, port, and egress intent.

## 5. Unencrypted storage

**References:** OWASP Top 10 2025 A04 (Cryptographic Failures), A02 (Security Misconfiguration);
OWASP ASVS 5.0 V11 (Data-at-Rest Protection), V14 (Data Protection); CWE-311 (Missing Encryption
of Sensitive Data).

**Vulnerable:** A database is public, unencrypted, and has no deletion recovery.

```hcl
resource "aws_db_instance" "orders_vulnerable" {
  identifier           = "example-orders"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}
```

**Fixed:** Place the database privately, encrypt storage with a customer-managed key, and retain
backups.

```hcl
resource "aws_db_instance" "orders_fixed" {
  identifier              = "example-orders"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.database.arn
  backup_retention_period  = 7
  deletion_protection      = true
  skip_final_snapshot      = false
  db_subnet_group_name     = aws_db_subnet_group.private.name
  vpc_security_group_ids   = [aws_security_group.database.id]
}
```

Encryption does not replace identity and network controls. Apply provider-equivalent encryption,
private placement, backup, and key-rotation settings to object, block, and database storage.

## 6. Missing or mutable audit trail

**References:** OWASP Top 10 2025 A09 (Security Logging and Monitoring Failures); OWASP ASVS 5.0
V16 (Security Logging and Monitoring); CWE-778 (Insufficient Logging).

**Vulnerable:** The trail omits global events, covers one region, skips validation, and writes to a
workload-controlled bucket.

```hcl
resource "aws_cloudtrail" "audit_vulnerable" {
  name                          = "example-audit"
  s3_bucket_name                = aws_s3_bucket.workload_logs.id
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = false
}
```

**Fixed:** Send an organisation-wide, tamper-evident trail to a protected security archive.

```hcl
resource "aws_cloudtrail" "audit_fixed" {
  name                          = "example-organisation-audit"
  s3_bucket_name                = aws_s3_bucket.security_archive.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  is_organization_trail         = true
}
```

The archive account must deny workload principals the ability to delete or rewrite logs. Alert on
identity, policy, logging, public-storage, metadata, unusual-assumption, and mass-deletion events.

## 7. Static workload identity

**References:** OWASP Top 10 2025 A01 (Broken Access Control), A02 (Security Misconfiguration);
OWASP ASVS 5.0 V8 (Authorization), V13 (Configuration); CWE-798 (Use of Hard-coded Credentials).

**Vulnerable:** A Kubernetes workload receives a long-lived cloud access key through a secret.

```hcl
resource "kubernetes_secret" "orders_key_vulnerable" {
  metadata { name = "example-orders-key" }
  data = {
    AWS_ACCESS_KEY_ID     = "placeholder-access-key"
    AWS_SECRET_ACCESS_KEY = "placeholder-secret-key"
  }
}
```

**Fixed:** Map the service account to a short-lived, scoped role through workload identity.

```hcl
resource "aws_iam_role" "orders_fixed" {
  name               = "example-orders-runtime"
  assume_role_policy = data.aws_iam_policy_document.orders_trust.json
}

resource "kubernetes_service_account" "orders_fixed" {
  metadata {
    name      = "orders"
    namespace = "example"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.orders_fixed.arn
    }
  }
}
```

Constrain the trust policy to the exact OIDC subject and audience, and grant only the role's
required actions. Use GKE Workload Identity Federation or Azure Workload ID equivalents; do not
place credentials in images, repositories, or manifests.

## 8. Cross-tenant key access

**References:** OWASP Top 10 2025 A01 (Broken Access Control), A04 (Cryptographic Failures);
OWASP ASVS 5.0 V8 (Authorization), V14 (Data Protection); CWE-863 (Incorrect Authorization).

**Vulnerable:** A shared encryption key policy permits every tenant role to decrypt every tenant's
ciphertext.

```hcl
data "aws_iam_policy_document" "shared_key_vulnerable" {
  statement {
    effect    = "Allow"
    principals { type = "AWS", identifiers = ["arn:aws:iam::${var.account_id}:root"] }
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = ["*"]
  }
}
```

**Fixed:** Use a tenant-scoped key or encryption context and authorize only the tenant workload.

```hcl
data "aws_iam_policy_document" "tenant_key_fixed" {
  statement {
    effect    = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/example-tenant-a-worker"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.tenant_a.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:tenant_id"
      values   = ["tenant-a-placeholder"]
    }
  }
}
```

Bind ciphertext access, object paths, and key permissions to the same tenant identifier. Validate
that tenant context is server-derived, not accepted from an untrusted request, and test denial for
another tenant before release.
