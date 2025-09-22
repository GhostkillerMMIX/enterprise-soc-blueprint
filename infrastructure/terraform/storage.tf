# Random string for unique bucket naming
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket for Splunk Cold Storage
resource "aws_s3_bucket" "splunk_cold_storage" {
  bucket = "${var.project_name}-splunk-cold-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-splunk-cold-storage"
    Environment = var.environment
    Purpose     = "Splunk Cold Storage"
  }
}

# S3 Bucket versioning for cold storage
resource "aws_s3_bucket_versioning" "splunk_cold_storage" {
  bucket = aws_s3_bucket.splunk_cold_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption for cold storage
resource "aws_s3_bucket_server_side_encryption_configuration" "splunk_cold_storage" {
  bucket = aws_s3_bucket.splunk_cold_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket lifecycle policy for cold storage
resource "aws_s3_bucket_lifecycle_configuration" "splunk_cold_storage" {
  bucket = aws_s3_bucket.splunk_cold_storage.id

  rule {
    id     = "splunk_cold_lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    transition {
      days          = 2555  # 7 years
      storage_class = "DEEP_ARCHIVE"
    }

    # Optional: Delete after 10 years for compliance
    # expiration {
    #   days = 3650
    # }
  }
}

# S3 Bucket for Splunk Apps
resource "aws_s3_bucket" "splunk_apps" {
  bucket = "${var.project_name}-splunk-apps-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-splunk-apps"
    Environment = var.environment
    Purpose     = "Splunk Applications"
  }
}

# S3 Bucket versioning for apps
resource "aws_s3_bucket_versioning" "splunk_apps" {
  bucket = aws_s3_bucket.splunk_apps.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption for apps
resource "aws_s3_bucket_server_side_encryption_configuration" "splunk_apps" {
  bucket = aws_s3_bucket.splunk_apps.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket for Splunk Lookups
resource "aws_s3_bucket" "splunk_lookups" {
  bucket = "${var.project_name}-splunk-lookups-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-splunk-lookups"
    Environment = var.environment
    Purpose     = "Splunk Lookup Tables"
  }
}

# S3 Bucket versioning for lookups
resource "aws_s3_bucket_versioning" "splunk_lookups" {
  bucket = aws_s3_bucket.splunk_lookups.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption for lookups
resource "aws_s3_bucket_server_side_encryption_configuration" "splunk_lookups" {
  bucket = aws_s3_bucket.splunk_lookups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket for SOAR Playbooks
resource "aws_s3_bucket" "soar_playbooks" {
  bucket = "${var.project_name}-soar-playbooks-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-soar-playbooks"
    Environment = var.environment
    Purpose     = "SOAR Playbooks and Artifacts"
  }
}

# S3 Bucket versioning for SOAR playbooks
resource "aws_s3_bucket_versioning" "soar_playbooks" {
  bucket = aws_s3_bucket.soar_playbooks.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption for SOAR playbooks
resource "aws_s3_bucket_server_side_encryption_configuration" "soar_playbooks" {
  bucket = aws_s3_bucket.soar_playbooks.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket for Backup Storage
resource "aws_s3_bucket" "backup_storage" {
  bucket = "${var.project_name}-backups-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-backups"
    Environment = var.environment
    Purpose     = "Configuration Backups"
  }
}

# S3 Bucket versioning for backups
resource "aws_s3_bucket_versioning" "backup_storage" {
  bucket = aws_s3_bucket.backup_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption for backups
resource "aws_s3_bucket_server_side_encryption_configuration" "backup_storage" {
  bucket = aws_s3_bucket.backup_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket lifecycle policy for backups
resource "aws_s3_bucket_lifecycle_configuration" "backup_storage" {
  bucket = aws_s3_bucket.backup_storage.id

  rule {
    id     = "backup_lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.backup_retention_days
    }
  }
}

# Block all public access on all buckets
resource "aws_s3_bucket_public_access_block" "splunk_cold_storage" {
  bucket = aws_s3_bucket.splunk_cold_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "splunk_apps" {
  bucket = aws_s3_bucket.splunk_apps.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "splunk_lookups" {
  bucket = aws_s3_bucket.splunk_lookups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "soar_playbooks" {
  bucket = aws_s3_bucket.soar_playbooks.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "backup_storage" {
  bucket = aws_s3_bucket.backup_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
