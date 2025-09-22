# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.soc_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.soc_vpc.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

# Splunk Outputs
output "splunk_web_url" {
  description = "URL for Splunk Web interface"
  value       = "http://${aws_lb.splunk_web.dns_name}"
}

output "splunk_web_internal_url" {
  description = "Internal URL for Splunk Web interface"
  value       = "http://splunk.${var.project_name}.local"
}

output "splunk_indexer_security_group_id" {
  description = "Security group ID for Splunk indexers"
  value       = aws_security_group.splunk_indexer.id
}

output "splunk_search_head_security_group_id" {
  description = "Security group ID for Splunk search heads"
  value       = aws_security_group.splunk_search_head.id
}

output "splunk_heavy_forwarder_security_group_id" {
  description = "Security group ID for Splunk heavy forwarders"
  value       = aws_security_group.splunk_heavy_forwarder.id
}

# SOAR Outputs
output "soar_url" {
  description = "URL for SOAR platform"
  value       = "https://${aws_lb.soar.dns_name}"
}

output "soar_internal_url" {
  description = "Internal URL for SOAR platform"
  value       = "https://soar.${var.project_name}.local"
}

output "soar_security_group_id" {
  description = "Security group ID for SOAR platform"
  value       = aws_security_group.soar.id
}

# Zeek Outputs
output "zeek_security_group_id" {
  description = "Security group ID for Zeek sensors"
  value       = aws_security_group.zeek.id
}

output "zeek_mirror_target_id" {
  description = "Traffic mirror target ID for Zeek"
  value       = aws_ec2_traffic_mirror_target.zeek.id
}

output "zeek_mirror_filter_id" {
  description = "Traffic mirror filter ID for Zeek"
  value       = aws_ec2_traffic_mirror_filter.zeek.id
}

# S3 Bucket Outputs
output "splunk_cold_storage_bucket" {
  description = "S3 bucket for Splunk cold storage"
  value       = aws_s3_bucket.splunk_cold_storage.bucket
}

output "splunk_apps_bucket" {
  description = "S3 bucket for Splunk apps"
  value       = aws_s3_bucket.splunk_apps.bucket
}

output "splunk_lookups_bucket" {
  description = "S3 bucket for Splunk lookups"
  value       = aws_s3_bucket.splunk_lookups.bucket
}

output "soar_playbooks_bucket" {
  description = "S3 bucket for SOAR playbooks"
  value       = aws_s3_bucket.soar_playbooks.bucket
}

output "zeek_logs_bucket" {
  description = "S3 bucket for Zeek logs"
  value       = aws_s3_bucket.zeek_logs.bucket
}

# IAM Role Outputs
output "splunk_indexer_role_arn" {
  description = "ARN of the Splunk indexer IAM role"
  value       = aws_iam_role.splunk_indexer.arn
}

output "splunk_search_head_role_arn" {
  description = "ARN of the Splunk search head IAM role"
  value       = aws_iam_role.splunk_search_head.arn
}

output "soar_role_arn" {
  description = "ARN of the SOAR IAM role"
  value       = aws_iam_role.soar.arn
}

output "zeek_role_arn" {
  description = "ARN of the Zeek IAM role"
  value       = aws_iam_role.zeek.arn
}

# Secrets Manager Outputs
output "splunk_secrets_arn" {
  description = "ARN of Splunk secrets in AWS Secrets Manager"
  value       = aws_secretsmanager_secret.splunk_secrets.arn
}

output "soar_secrets_arn" {
  description = "ARN of SOAR secrets in AWS Secrets Manager"
  value       = aws_secretsmanager_secret.soar_secrets.arn
}

# Route53 Outputs
output "private_zone_id" {
  description = "Route53 private hosted zone ID"
  value       = aws_route53_zone.private.zone_id
}

output "private_zone_name" {
  description = "Route53 private hosted zone name"
  value       = aws_route53_zone.private.name
}

# Monitoring Outputs
output "sns_alerts_topic_arn" {
  description = "ARN of SNS topic for alerts"
  value       = var.enable_monitoring ? aws_sns_topic.alerts[0].arn : null
}

output "cloudwatch_log_group_vpc_flow_logs" {
  description = "CloudWatch log group for VPC flow logs"
  value       = var.enable_logging ? aws_cloudwatch_log_group.vpc_flow_log[0].name : null
}

# Load Balancer Outputs
output "splunk_alb_dns_name" {
  description = "DNS name of Splunk ALB"
  value       = aws_lb.splunk_web.dns_name
}

output "splunk_alb_zone_id" {
  description = "Zone ID of Splunk ALB"
  value       = aws_lb.splunk_web.zone_id
}

output "soar_alb_dns_name" {
  description = "DNS name of SOAR ALB"
  value       = aws_lb.soar.dns_name
}

output "soar_alb_zone_id" {
  description = "Zone ID of SOAR ALB"
  value       = aws_lb.soar.zone_id
}

# Auto Scaling Group Outputs
output "splunk_indexer_asg_name" {
  description = "Name of Splunk indexer Auto Scaling Group"
  value       = aws_autoscaling_group.splunk_indexer.name
}

output "splunk_search_head_asg_name" {
  description = "Name of Splunk search head Auto Scaling Group"
  value       = aws_autoscaling_group.splunk_search_head.name
}

output "soar_asg_name" {
  description = "Name of SOAR Auto Scaling Group"
  value       = aws_autoscaling_group.soar.name
}

output "zeek_asg_name" {
  description = "Name of Zeek Auto Scaling Group"
  value       = aws_autoscaling_group.zeek.name
}

# Configuration Outputs for Ansible
output "ansible_inventory" {
  description = "Ansible inventory information"
  value = {
    splunk_indexers = {
      hosts = []  # Will be populated by Auto Scaling Groups
      vars = {
        splunk_role = "indexer"
        splunk_cluster_master = "cluster-master.${var.project_name}.local"
      }
    }
    splunk_search_heads = {
      hosts = []  # Will be populated by Auto Scaling Groups
      vars = {
        splunk_role = "search_head"
        splunk_cluster_master = "cluster-master.${var.project_name}.local"
      }
    }
    soar_servers = {
      hosts = []  # Will be populated by Auto Scaling Groups
      vars = {
        soar_role = "primary"
      }
    }
    zeek_sensors = {
      hosts = []  # Will be populated by Auto Scaling Groups
      vars = {
        zeek_role = "sensor"
      }
    }
  }
}

# Environment Information
output "deployment_info" {
  description = "Deployment information"
  value = {
    environment    = var.environment
    project_name   = var.project_name
    aws_region     = var.aws_region
    deployment_date = timestamp()
  }
}
