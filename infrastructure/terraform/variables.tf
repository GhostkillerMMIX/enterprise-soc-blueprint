# General Configuration
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "owner" {
  description = "Owner of the resources"
  type        = string
  default     = "security-team"
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "enterprise-soc"
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# Splunk Configuration
variable "splunk_indexer_count" {
  description = "Number of Splunk indexers"
  type        = number
  default     = 3
}

variable "splunk_indexer_instance_type" {
  description = "Instance type for Splunk indexers"
  type        = string
  default     = "c5.4xlarge"  # 16 vCPU, 32GB RAM
}

variable "splunk_search_head_count" {
  description = "Number of Splunk search heads"
  type        = number
  default     = 2
}

variable "splunk_search_head_instance_type" {
  description = "Instance type for Splunk search heads"
  type        = string
  default     = "c5.2xlarge"  # 8 vCPU, 16GB RAM
}

variable "splunk_heavy_forwarder_count" {
  description = "Number of Splunk heavy forwarders"
  type        = number
  default     = 1
}

variable "splunk_heavy_forwarder_instance_type" {
  description = "Instance type for Splunk heavy forwarders"
  type        = string
  default     = "c5.large"  # 2 vCPU, 4GB RAM
}

variable "splunk_license_file" {
  description = "Path to Splunk license file"
  type        = string
  default     = ""
}

variable "splunk_admin_password" {
  description = "Splunk admin password"
  type        = string
  sensitive   = true
}

# SOAR Configuration
variable "soar_instance_type" {
  description = "Instance type for SOAR platform"
  type        = string
  default     = "c5.2xlarge"  # 8 vCPU, 16GB RAM
}

variable "soar_instance_count" {
  description = "Number of SOAR instances"
  type        = number
  default     = 1
}

# Zeek Configuration
variable "zeek_instance_type" {
  description = "Instance type for Zeek sensor"
  type        = string
  default     = "c5.xlarge"  # 4 vCPU, 8GB RAM
}

variable "zeek_instance_count" {
  description = "Number of Zeek sensors"
  type        = number
  default     = 1
}

# Storage Configuration
variable "indexer_hot_storage_size" {
  description = "Hot storage size for indexers (GB)"
  type        = number
  default     = 1000
}

variable "indexer_warm_storage_size" {
  description = "Warm storage size for indexers (GB)"
  type        = number
  default     = 2000
}

# Security Configuration
variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access SOC infrastructure"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "ssh_key_name" {
  description = "Name of AWS key pair for SSH access"
  type        = string
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable VPC Flow Logs and CloudTrail"
  type        = bool
  default     = true
}

# Backup Configuration
variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Use spot instances for non-critical components"
  type        = bool
  default     = false
}

variable "auto_scaling_enabled" {
  description = "Enable auto-scaling for applicable components"
  type        = bool
  default     = true
}

# Integration Configuration
variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "email_notifications" {
  description = "Email addresses for notifications"
  type        = list(string)
  default     = []
}
