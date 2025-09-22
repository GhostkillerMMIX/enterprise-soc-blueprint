# Infrastructure Setup Guide

This guide walks you through setting up the foundational infrastructure for the Enterprise SOC using Terraform.

## Prerequisites

### Required Tools
- **Terraform** >= 1.0
- **AWS CLI** >= 2.0
- **Git**
- **jq** (for JSON processing)

### AWS Requirements
- AWS Account with administrative privileges
- AWS CLI configured with appropriate credentials
- Route53 hosted zone (optional, for custom domains)

### Permissions Required
Your AWS user/role needs the following permissions:
- EC2 (full access)
- VPC (full access)
- IAM (full access)
- S3 (full access)
- Route53 (if using custom domains)
- CloudWatch (full access)
- Auto Scaling (full access)
- Elastic Load Balancing (full access)
- Secrets Manager (full access)
- Systems Manager Parameter Store (full access)

## Step 1: Clone and Configure

### 1.1 Clone the Repository
```bash
git clone https://github.com/your-org/enterprise-soc-blueprint.git
cd enterprise-soc-blueprint
```

### 1.2 Create SSH Key Pair
Create an SSH key pair for accessing EC2 instances:

```bash
# Create key pair in AWS
aws ec2 create-key-pair \
  --key-name soc-keypair \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/soc-keypair.pem

# Set proper permissions
chmod 400 ~/.ssh/soc-keypair.pem
```

### 1.3 Configure Terraform Variables
Copy the example variables file and customize it:

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your specific configuration:

```hcl
# General Configuration
environment = "prod"
owner = "security-team"
aws_region = "us-east-1"
project_name = "enterprise-soc"

# Network Configuration
vpc_cidr = "10.0.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
public_subnet_cidrs = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

# Splunk Configuration
splunk_indexer_count = 3
splunk_indexer_instance_type = "c5.4xlarge"
splunk_search_head_count = 2
splunk_search_head_instance_type = "c5.2xlarge"
splunk_heavy_forwarder_count = 1
splunk_heavy_forwarder_instance_type = "c5.large"

# SOAR Configuration
soar_instance_type = "c5.2xlarge"
soar_instance_count = 1

# Zeek Configuration
zeek_instance_type = "c5.xlarge"
zeek_instance_count = 1

# Storage Configuration
indexer_hot_storage_size = 1000  # GB
indexer_warm_storage_size = 2000  # GB

# Security Configuration
allowed_cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
ssh_key_name = "soc-keypair"

# Splunk Admin Password (use AWS Secrets Manager in production)
splunk_admin_password = "YourSecurePassword123!"

# Monitoring Configuration
enable_monitoring = true
enable_logging = true
backup_retention_days = 30

# Notification Configuration
email_notifications = ["security-team@company.com"]
slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

## Step 2: Infrastructure Deployment

### 2.1 Initialize Terraform
```bash
cd infrastructure/terraform
terraform init
```

### 2.2 Plan the Deployment
```bash
terraform plan -out=tfplan
```

Review the plan carefully. You should see resources for:
- VPC with public and private subnets
- Security groups for each component
- Auto Scaling Groups for Splunk, SOAR, and Zeek
- Application Load Balancers
- S3 buckets for storage
- IAM roles and policies
- Route53 private hosted zone
- CloudWatch monitoring resources

### 2.3 Apply the Configuration
```bash
terraform apply tfplan
```

This will take approximately 10-15 minutes to complete.

### 2.4 Save Outputs
```bash
terraform output -json > ../../outputs/terraform-outputs.json
```

## Step 3: Verification

### 3.1 Verify Infrastructure
```bash
# Check VPC
aws ec2 describe-vpcs --filters "Name=tag:Project,Values=Enterprise-SOC"

# Check instances
aws ec2 describe-instances --filters "Name=tag:Project,Values=Enterprise-SOC" "Name=instance-state-name,Values=running"

# Check load balancers
aws elbv2 describe-load-balancers --names "*enterprise-soc*"

# Check S3 buckets
aws s3 ls | grep enterprise-soc
```

### 3.2 Run Validation Script
```bash
cd ../..
./scripts/validation/validate-infrastructure.sh
```

## Step 4: Post-Deployment Configuration

### 4.1 Configure DNS (Optional)
If you have a custom domain, update your DNS to point to the load balancers:

```bash
# Get load balancer DNS names
SPLUNK_ALB_DNS=$(terraform output -json | jq -r '.splunk_alb_dns_name.value')
SOAR_ALB_DNS=$(terraform output -json | jq -r '.soar_alb_dns_name.value')

echo "Splunk Web: $SPLUNK_ALB_DNS"
echo "SOAR Platform: $SOAR_ALB_DNS"
```

### 4.2 Update Security Groups (if needed)
If you need to allow access from additional IP ranges:

```bash
# Add your office IP to Splunk security group
OFFICE_IP="203.0.113.0/24"  # Replace with your IP
SPLUNK_SG_ID=$(terraform output -json | jq -r '.splunk_search_head_security_group_id.value')

aws ec2 authorize-security-group-ingress \
  --group-id $SPLUNK_SG_ID \
  --protocol tcp \
  --port 8000 \
  --cidr $OFFICE_IP
```

## Step 5: Troubleshooting

### Common Issues

#### 5.1 Terraform Apply Fails
**Issue**: Resource creation fails due to permissions
**Solution**: 
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify required permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names ec2:CreateVpc \
  --resource-arns "*"
```

#### 5.2 Instance Launch Failures
**Issue**: EC2 instances fail to launch
**Solution**:
```bash
# Check Auto Scaling Group events
ASG_NAME=$(terraform output -json | jq -r '.splunk_indexer_asg_name.value')
aws autoscaling describe-scaling-activities --auto-scaling-group-name $ASG_NAME
```

#### 5.3 Load Balancer Target Health
**Issue**: Load balancer targets are unhealthy
**Solution**:
```bash
# Check target group health
ALB_ARN=$(terraform output -json | jq -r '.splunk_alb_arn.value')
TARGET_GROUPS=$(aws elbv2 describe-target-groups --load-balancer-arn $ALB_ARN --query 'TargetGroups[].TargetGroupArn' --output text)

for TG in $TARGET_GROUPS; do
  aws elbv2 describe-target-health --target-group-arn $TG
done
```

### Logs and Monitoring

#### CloudWatch Logs
Check CloudWatch logs for troubleshooting:
```bash
# List log groups
aws logs describe-log-groups --log-group-name-prefix "/aws/ec2/enterprise-soc"

# View recent logs
aws logs tail /aws/ec2/enterprise-soc/indexer --follow
```

#### VPC Flow Logs
```bash
# Check VPC Flow Logs
VPC_ID=$(terraform output -json | jq -r '.vpc_id.value')
aws ec2 describe-flow-logs --filters "Name=resource-id,Values=$VPC_ID"
```

## Step 6: Cost Optimization

### 6.1 Right-sizing Instances
Monitor instance utilization and adjust sizes:

```bash
# Check CPU utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=AutoScalingGroupName,Value=enterprise-soc-indexer-asg \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### 6.2 Storage Optimization
- Monitor S3 storage usage
- Configure lifecycle policies for cold storage
- Use S3 Intelligent Tiering for automatic optimization

### 6.3 Reserved Instances
For production environments, consider purchasing Reserved Instances for predictable workloads.

## Step 7: Security Hardening

### 7.1 Network Security
- Review security group rules
- Enable VPC Flow Logs
- Configure AWS Config for compliance monitoring

### 7.2 Access Control
- Implement least-privilege IAM policies
- Enable CloudTrail for audit logging
- Configure MFA for administrative access

### 7.3 Encryption
- Verify EBS encryption is enabled
- Configure S3 bucket encryption
- Use AWS Secrets Manager for sensitive data

## Next Steps

Once infrastructure deployment is complete:

1. **[Deploy Applications](02-splunk-deployment.md)** - Install and configure Splunk cluster
2. **[Configure SOAR](03-soar-setup.md)** - Set up SOAR platform and playbooks
3. **[Implement Detection Rules](04-detection-rules.md)** - Deploy security detection rules
4. **[Validation and Testing](05-validation.md)** - Comprehensive testing and validation

## Support

For issues with infrastructure deployment:
- Check the troubleshooting section above
- Review Terraform logs: `terraform apply` output
- Check AWS CloudFormation events (if using)
- Consult the [FAQ](../faq.md) for common questions

---

**Next**: [Splunk Cluster Deployment](02-splunk-deployment.md)
