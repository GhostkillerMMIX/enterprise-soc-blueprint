# AWS Secrets Manager Secret for Splunk
resource "aws_secretsmanager_secret" "splunk_secrets" {
  name        = "${var.project_name}-splunk-secrets"
  description = "Secrets for Splunk deployment"

  tags = {
    Name        = "${var.project_name}-splunk-secrets"
    Environment = var.environment
  }
}

# Splunk Secrets Version
resource "aws_secretsmanager_secret_version" "splunk_secrets" {
  secret_id = aws_secretsmanager_secret.splunk_secrets.id
  secret_string = jsonencode({
    admin_password      = var.splunk_admin_password
    secret_key         = random_password.splunk_secret_key.result
    cluster_key        = random_password.splunk_cluster_key.result
    indexer_discovery  = random_password.splunk_indexer_discovery.result
    pass4SymmKey       = random_password.splunk_pass4symmkey.result
  })
}

# AWS Secrets Manager Secret for SOAR
resource "aws_secretsmanager_secret" "soar_secrets" {
  name        = "${var.project_name}-soar-secrets"
  description = "Secrets for SOAR deployment"

  tags = {
    Name        = "${var.project_name}-soar-secrets"
    Environment = var.environment
  }
}

# SOAR Secrets Version
resource "aws_secretsmanager_secret_version" "soar_secrets" {
  secret_id = aws_secretsmanager_secret.soar_secrets.id
  secret_string = jsonencode({
    admin_password = random_password.soar_admin_password.result
    api_key       = random_password.soar_api_key.result
    db_password   = random_password.soar_db_password.result
    encryption_key = random_password.soar_encryption_key.result
  })
}

# Random passwords for Splunk
resource "random_password" "splunk_secret_key" {
  length  = 32
  special = true
}

resource "random_password" "splunk_cluster_key" {
  length  = 32
  special = true
}

resource "random_password" "splunk_indexer_discovery" {
  length  = 32
  special = true
}

resource "random_password" "splunk_pass4symmkey" {
  length  = 32
  special = true
}

# Random passwords for SOAR
resource "random_password" "soar_admin_password" {
  length  = 16
  special = true
}

resource "random_password" "soar_api_key" {
  length  = 64
  special = false
  upper   = true
  lower   = true
  numeric = true
}

resource "random_password" "soar_db_password" {
  length  = 32
  special = true
}

resource "random_password" "soar_encryption_key" {
  length  = 32
  special = false
  upper   = true
  lower   = true
  numeric = true
}

# SSM Parameters for non-sensitive configuration
resource "aws_ssm_parameter" "splunk_cluster_master" {
  name  = "/${var.project_name}/splunk/cluster_master"
  type  = "String"
  value = "cluster-master.${var.project_name}.local"

  tags = {
    Name        = "${var.project_name}-cluster-master"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "splunk_deployment_server" {
  name  = "/${var.project_name}/splunk/deployment_server"
  type  = "String"
  value = "deployment-server.${var.project_name}.local"

  tags = {
    Name        = "${var.project_name}-deployment-server"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "splunk_license_master" {
  name  = "/${var.project_name}/splunk/license_master"
  type  = "String"
  value = "license-master.${var.project_name}.local"

  tags = {
    Name        = "${var.project_name}-license-master"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "soar_url" {
  name  = "/${var.project_name}/soar/url"
  type  = "String"
  value = "https://soar.${var.project_name}.local"

  tags = {
    Name        = "${var.project_name}-soar-url"
    Environment = var.environment
  }
}

# SSM Parameter for S3 bucket names
resource "aws_ssm_parameter" "splunk_cold_bucket" {
  name  = "/${var.project_name}/s3/splunk_cold_storage"
  type  = "String"
  value = aws_s3_bucket.splunk_cold_storage.bucket

  tags = {
    Name        = "${var.project_name}-cold-storage-bucket"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "splunk_apps_bucket" {
  name  = "/${var.project_name}/s3/splunk_apps"
  type  = "String"
  value = aws_s3_bucket.splunk_apps.bucket

  tags = {
    Name        = "${var.project_name}-apps-bucket"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "splunk_lookups_bucket" {
  name  = "/${var.project_name}/s3/splunk_lookups"
  type  = "String"
  value = aws_s3_bucket.splunk_lookups.bucket

  tags = {
    Name        = "${var.project_name}-lookups-bucket"
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "soar_playbooks_bucket" {
  name  = "/${var.project_name}/s3/soar_playbooks"
  type  = "String"
  value = aws_s3_bucket.soar_playbooks.bucket

  tags = {
    Name        = "${var.project_name}-playbooks-bucket"
    Environment = var.environment
  }
}

# SSM Parameter for monitoring configuration
resource "aws_ssm_parameter" "sns_alerts_topic" {
  count = var.enable_monitoring ? 1 : 0

  name  = "/${var.project_name}/monitoring/sns_alerts_topic"
  type  = "String"
  value = aws_sns_topic.alerts[0].arn

  tags = {
    Name        = "${var.project_name}-sns-alerts-topic"
    Environment = var.environment
  }
}

# KMS Key for additional encryption (optional)
resource "aws_kms_key" "soc_key" {
  description             = "KMS key for ${var.project_name} SOC encryption"
  deletion_window_in_days = 7

  tags = {
    Name        = "${var.project_name}-soc-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "soc_key" {
  name          = "alias/${var.project_name}-soc"
  target_key_id = aws_kms_key.soc_key.key_id
}

# KMS Key Policy
resource "aws_kms_key_policy" "soc_key" {
  key_id = aws_kms_key.soc_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.splunk_indexer.arn,
            aws_iam_role.splunk_search_head.arn,
            aws_iam_role.soar.arn,
            aws_iam_role.zeek.arn
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
