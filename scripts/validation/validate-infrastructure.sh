#!/bin/bash

# Infrastructure Validation Script
# Validates that all SOC infrastructure components are properly deployed and configured

set -e

# Configuration
LOG_FILE="/tmp/validation-results.log"
TERRAFORM_OUTPUTS="outputs/terraform-outputs.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
PASSED_TESTS=0
FAILED_TESTS=0
TOTAL_TESTS=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_FILE"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

test_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
    ((TOTAL_TESTS++))
}

# Check if Terraform outputs exist
check_terraform_outputs() {
    log "Checking Terraform outputs..."
    
    if [[ ! -f "$TERRAFORM_OUTPUTS" ]]; then
        test_fail "Terraform outputs file not found: $TERRAFORM_OUTPUTS"
        return 1
    fi
    
    # Validate JSON format
    if ! jq empty "$TERRAFORM_OUTPUTS" 2>/dev/null; then
        test_fail "Terraform outputs file is not valid JSON"
        return 1
    fi
    
    test_pass "Terraform outputs file exists and is valid JSON"
}

# Validate VPC and networking
validate_vpc() {
    log "Validating VPC and networking..."
    
    local vpc_id=$(jq -r '.vpc_id.value' "$TERRAFORM_OUTPUTS")
    
    if [[ "$vpc_id" == "null" || -z "$vpc_id" ]]; then
        test_fail "VPC ID not found in Terraform outputs"
        return 1
    fi
    
    # Check if VPC exists
    if aws ec2 describe-vpcs --vpc-ids "$vpc_id" &>/dev/null; then
        test_pass "VPC exists: $vpc_id"
    else
        test_fail "VPC not found in AWS: $vpc_id"
        return 1
    fi
    
    # Check subnets
    local private_subnets=$(jq -r '.private_subnet_ids.value[]' "$TERRAFORM_OUTPUTS" 2>/dev/null)
    local public_subnets=$(jq -r '.public_subnet_ids.value[]' "$TERRAFORM_OUTPUTS" 2>/dev/null)
    
    local private_count=$(echo "$private_subnets" | wc -l)
    local public_count=$(echo "$public_subnets" | wc -l)
    
    if [[ $private_count -ge 2 ]]; then
        test_pass "Sufficient private subnets: $private_count"
    else
        test_fail "Insufficient private subnets: $private_count (minimum 2 required)"
    fi
    
    if [[ $public_count -ge 2 ]]; then
        test_pass "Sufficient public subnets: $public_count"
    else
        test_warning "Limited public subnets: $public_count (recommended 2+)"
    fi
    
    # Check internet gateway
    local igw_id=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpc_id" --query 'InternetGateways[0].InternetGatewayId' --output text)
    
    if [[ "$igw_id" != "None" && "$igw_id" != "null" ]]; then
        test_pass "Internet Gateway attached to VPC"
    else
        test_fail "No Internet Gateway found for VPC"
    fi
    
    # Check NAT Gateways
    local nat_count=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$vpc_id" --query 'NatGateways[?State==`available`]' --output json | jq length)
    
    if [[ $nat_count -ge 1 ]]; then
        test_pass "NAT Gateways available: $nat_count"
    else
        test_fail "No available NAT Gateways found"
    fi
}

# Validate security groups
validate_security_groups() {
    log "Validating security groups..."
    
    local vpc_id=$(jq -r '.vpc_id.value' "$TERRAFORM_OUTPUTS")
    
    # Check Splunk security groups
    local splunk_indexer_sg=$(jq -r '.splunk_indexer_security_group_id.value' "$TERRAFORM_OUTPUTS")
    local splunk_search_head_sg=$(jq -r '.splunk_search_head_security_group_id.value' "$TERRAFORM_OUTPUTS")
    local soar_sg=$(jq -r '.soar_security_group_id.value' "$TERRAFORM_OUTPUTS")
    local zeek_sg=$(jq -r '.zeek_security_group_id.value' "$TERRAFORM_OUTPUTS")
    
    local security_groups=("$splunk_indexer_sg" "$splunk_search_head_sg" "$soar_sg" "$zeek_sg")
    local sg_names=("Splunk Indexer" "Splunk Search Head" "SOAR" "Zeek")
    
    for i in "${!security_groups[@]}"; do
        local sg_id="${security_groups[$i]}"
        local sg_name="${sg_names[$i]}"
        
        if [[ "$sg_id" != "null" && -n "$sg_id" ]]; then
            if aws ec2 describe-security-groups --group-ids "$sg_id" &>/dev/null; then
                test_pass "$sg_name security group exists: $sg_id"
            else
                test_fail "$sg_name security group not found: $sg_id"
            fi
        else
            test_fail "$sg_name security group ID not found in outputs"
        fi
    done
    
    # Validate security group rules
    validate_security_group_rules "$splunk_indexer_sg" "Splunk Indexer" "9997,8089,9887"
    validate_security_group_rules "$splunk_search_head_sg" "Splunk Search Head" "8000,8089"
    validate_security_group_rules "$soar_sg" "SOAR" "443,80"
}

# Validate specific security group rules
validate_security_group_rules() {
    local sg_id="$1"
    local sg_name="$2"
    local required_ports="$3"
    
    if [[ "$sg_id" == "null" || -z "$sg_id" ]]; then
        return 1
    fi
    
    local sg_rules=$(aws ec2 describe-security-groups --group-ids "$sg_id" --query 'SecurityGroups[0].IpPermissions' --output json)
    
    IFS=',' read -ra PORTS <<< "$required_ports"
    for port in "${PORTS[@]}"; do
        local port_open=$(echo "$sg_rules" | jq --arg port "$port" '.[] | select(.FromPort == ($port | tonumber)) | length > 0')
        
        if [[ "$port_open" == "true" ]]; then
            test_pass "$sg_name allows traffic on port $port"
        else
            test_fail "$sg_name missing rule for port $port"
        fi
    done
}

# Validate EC2 instances
validate_ec2_instances() {
    log "Validating EC2 instances..."
    
    # Get Auto Scaling Groups from outputs
    local indexer_asg=$(jq -r '.splunk_indexer_asg_name.value' "$TERRAFORM_OUTPUTS")
    local search_head_asg=$(jq -r '.splunk_search_head_asg_name.value' "$TERRAFORM_OUTPUTS")
    local soar_asg=$(jq -r '.soar_asg_name.value' "$TERRAFORM_OUTPUTS")
    local zeek_asg=$(jq -r '.zeek_asg_name.value' "$TERRAFORM_OUTPUTS")
    
    local asgs=("$indexer_asg" "$search_head_asg" "$soar_asg" "$zeek_asg")
    local asg_names=("Splunk Indexer" "Splunk Search Head" "SOAR" "Zeek")
    
    for i in "${!asgs[@]}"; do
        local asg_name="${asgs[$i]}"
        local component_name="${asg_names[$i]}"
        
        if [[ "$asg_name" != "null" && -n "$asg_name" ]]; then
            # Check ASG exists
            local asg_info=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg_name" --query 'AutoScalingGroups[0]' --output json 2>/dev/null)
            
            if [[ -n "$asg_info" && "$asg_info" != "null" ]]; then
                test_pass "$component_name Auto Scaling Group exists: $asg_name"
                
                # Check instance count
                local desired_capacity=$(echo "$asg_info" | jq -r '.DesiredCapacity')
                local running_instances=$(echo "$asg_info" | jq -r '.Instances | map(select(.LifecycleState == "InService")) | length')
                
                if [[ "$running_instances" -eq "$desired_capacity" && "$running_instances" -gt 0 ]]; then
                    test_pass "$component_name has $running_instances/$desired_capacity healthy instances"
                else
                    test_fail "$component_name has $running_instances/$desired_capacity healthy instances"
                fi
                
                # Check instance health
                local unhealthy_count=$(echo "$asg_info" | jq -r '.Instances | map(select(.HealthStatus != "Healthy")) | length')
                if [[ "$unhealthy_count" -eq 0 ]]; then
                    test_pass "$component_name all instances are healthy"
                else
                    test_fail "$component_name has $unhealthy_count unhealthy instances"
                fi
            else
                test_fail "$component_name Auto Scaling Group not found: $asg_name"
            fi
        else
            test_fail "$component_name ASG name not found in outputs"
        fi
    done
}

# Validate Load Balancers
validate_load_balancers() {
    log "Validating load balancers..."
    
    local splunk_alb_dns=$(jq -r '.splunk_alb_dns_name.value' "$TERRAFORM_OUTPUTS")
    local soar_alb_dns=$(jq -r '.soar_alb_dns_name.value' "$TERRAFORM_OUTPUTS")
    
    # Check Splunk ALB
    if [[ "$splunk_alb_dns" != "null" && -n "$splunk_alb_dns" ]]; then
        local splunk_alb_arn=$(aws elbv2 describe-load-balancers --names "*splunk*" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")
        
        if [[ "$splunk_alb_arn" != "None" ]]; then
            test_pass "Splunk ALB exists: $splunk_alb_dns"
            
            # Check target group health
            local target_groups=$(aws elbv2 describe-target-groups --load-balancer-arn "$splunk_alb_arn" --query 'TargetGroups[].TargetGroupArn' --output text)
            
            for tg_arn in $target_groups; do
                local healthy_targets=$(aws elbv2 describe-target-health --target-group-arn "$tg_arn" --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`]' --output json | jq length)
                local total_targets=$(aws elbv2 describe-target-health --target-group-arn "$tg_arn" --query 'TargetHealthDescriptions' --output json | jq length)
                
                if [[ "$healthy_targets" -gt 0 ]]; then
                    test_pass "Splunk ALB has $healthy_targets/$total_targets healthy targets"
                else
                    test_fail "Splunk ALB has no healthy targets ($total_targets total)"
                fi
            done
        else
            test_fail "Splunk ALB not found"
        fi
    else
        test_fail "Splunk ALB DNS name not found in outputs"
    fi
    
    # Check SOAR ALB
    if [[ "$soar_alb_dns" != "null" && -n "$soar_alb_dns" ]]; then
        local soar_alb_arn=$(aws elbv2 describe-load-balancers --names "*soar*" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")
        
        if [[ "$soar_alb_arn" != "None" ]]; then
            test_pass "SOAR ALB exists: $soar_alb_dns"
        else
            test_fail "SOAR ALB not found"
        fi
    else
        test_fail "SOAR ALB DNS name not found in outputs"
    fi
}

# Validate S3 buckets
validate_s3_buckets() {
    log "Validating S3 buckets..."
    
    local cold_storage_bucket=$(jq -r '.splunk_cold_storage_bucket.value' "$TERRAFORM_OUTPUTS")
    local apps_bucket=$(jq -r '.splunk_apps_bucket.value' "$TERRAFORM_OUTPUTS")
    local lookups_bucket=$(jq -r '.splunk_lookups_bucket.value' "$TERRAFORM_OUTPUTS")
    local playbooks_bucket=$(jq -r '.soar_playbooks_bucket.value' "$TERRAFORM_OUTPUTS")
    
    local buckets=("$cold_storage_bucket" "$apps_bucket" "$lookups_bucket" "$playbooks_bucket")
    local bucket_names=("Cold Storage" "Apps" "Lookups" "SOAR Playbooks")
    
    for i in "${!buckets[@]}"; do
        local bucket="${buckets[$i]}"
        local bucket_name="${bucket_names[$i]}"
        
        if [[ "$bucket" != "null" && -n "$bucket" ]]; then
            if aws s3 ls "s3://$bucket" &>/dev/null; then
                test_pass "$bucket_name S3 bucket exists: $bucket"
                
                # Check bucket encryption
                local encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "None")
                
                if [[ "$encryption" != "None" ]]; then
                    test_pass "$bucket_name bucket has encryption enabled: $encryption"
                else
                    test_warning "$bucket_name bucket encryption not configured"
                fi
                
                # Check public access block
                local public_access=$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration.BlockPublicAcls' --output text 2>/dev/null || echo "false")
                
                if [[ "$public_access" == "true" ]]; then
                    test_pass "$bucket_name bucket has public access blocked"
                else
                    test_fail "$bucket_name bucket allows public access"
                fi
            else
                test_fail "$bucket_name S3 bucket not accessible: $bucket"
            fi
        else
            test_fail "$bucket_name bucket name not found in outputs"
        fi
    done
}

# Validate IAM roles and policies
validate_iam_roles() {
    log "Validating IAM roles..."
    
    local indexer_role_arn=$(jq -r '.splunk_indexer_role_arn.value' "$TERRAFORM_OUTPUTS")
    local search_head_role_arn=$(jq -r '.splunk_search_head_role_arn.value' "$TERRAFORM_OUTPUTS")
    local soar_role_arn=$(jq -r '.soar_role_arn.value' "$TERRAFORM_OUTPUTS")
    local zeek_role_arn=$(jq -r '.zeek_role_arn.value' "$TERRAFORM_OUTPUTS")
    
    local role_arns=("$indexer_role_arn" "$search_head_role_arn" "$soar_role_arn" "$zeek_role_arn")
    local role_names=("Splunk Indexer" "Splunk Search Head" "SOAR" "Zeek")
    
    for i in "${!role_arns[@]}"; do
        local role_arn="${role_arns[$i]}"
        local role_name="${role_names[$i]}"
        
        if [[ "$role_arn" != "null" && -n "$role_arn" ]]; then
            local role_name_only=$(echo "$role_arn" | awk -F'/' '{print $NF}')
            
            if aws iam get-role --role-name "$role_name_only" &>/dev/null; then
                test_pass "$role_name IAM role exists: $role_name_only"
                
                # Check if role has policies attached
                local policy_count=$(aws iam list-attached-role-policies --role-name "$role_name_only" --query 'AttachedPolicies' --output json | jq length)
                local inline_policy_count=$(aws iam list-role-policies --role-name "$role_name_only" --query 'PolicyNames' --output json | jq length)
                
                local total_policies=$((policy_count + inline_policy_count))
                
                if [[ $total_policies -gt 0 ]]; then
                    test_pass "$role_name role has $total_policies policies attached"
                else
                    test_warning "$role_name role has no policies attached"
                fi
            else
                test_fail "$role_name IAM role not found: $role_name_only"
            fi
        else
            test_fail "$role_name role ARN not found in outputs"
        fi
    done
}

# Validate DNS and Route53
validate_dns() {
    log "Validating DNS and Route53..."
    
    local private_zone_id=$(jq -r '.private_zone_id.value' "$TERRAFORM_OUTPUTS")
    local private_zone_name=$(jq -r '.private_zone_name.value' "$TERRAFORM_OUTPUTS")
    
    if [[ "$private_zone_id" != "null" && -n "$private_zone_id" ]]; then
        if aws route53 get-hosted-zone --id "$private_zone_id" &>/dev/null; then
            test_pass "Private hosted zone exists: $private_zone_name ($private_zone_id)"
            
            # Check DNS records
            local record_count=$(aws route53 list-resource-record-sets --hosted-zone-id "$private_zone_id" --query 'ResourceRecordSets[?Type==`A`]' --output json | jq length)
            
            if [[ $record_count -gt 2 ]]; then  # More than SOA and NS records
                test_pass "Private zone has $record_count A records"
            else
                test_warning "Private zone has limited DNS records: $record_count"
            fi
        else
            test_fail "Private hosted zone not accessible: $private_zone_id"
        fi
    else
        test_fail "Private zone ID not found in outputs"
    fi
}

# Validate monitoring setup
validate_monitoring() {
    log "Validating monitoring setup..."
    
    local sns_topic_arn=$(jq -r '.sns_alerts_topic_arn.value' "$TERRAFORM_OUTPUTS")
    
    if [[ "$sns_topic_arn" != "null" && -n "$sns_topic_arn" ]]; then
        local topic_name=$(echo "$sns_topic_arn" | awk -F':' '{print $NF}')
        
        if aws sns get-topic-attributes --topic-arn "$sns_topic_arn" &>/dev/null; then
            test_pass "SNS alerts topic exists: $topic_name"
            
            # Check subscriptions
            local subscription_count=$(aws sns list-subscriptions-by-topic --topic-arn "$sns_topic_arn" --query 'Subscriptions' --output json | jq length)
            
            if [[ $subscription_count -gt 0 ]]; then
                test_pass "SNS topic has $subscription_count subscriptions"
            else
                test_warning "SNS topic has no subscriptions configured"
            fi
        else
            test_fail "SNS alerts topic not accessible: $sns_topic_arn"
        fi
    else
        test_warning "SNS alerts topic not configured"
    fi
    
    # Check CloudWatch log groups
    local vpc_flow_log_group=$(jq -r '.cloudwatch_log_group_vpc_flow_logs.value' "$TERRAFORM_OUTPUTS")
    
    if [[ "$vpc_flow_log_group" != "null" && -n "$vpc_flow_log_group" ]]; then
        if aws logs describe-log-groups --log-group-name-prefix "$vpc_flow_log_group" --query 'logGroups[0]' --output json | jq -e 'has("logGroupName")' &>/dev/null; then
            test_pass "VPC Flow Logs CloudWatch group exists: $vpc_flow_log_group"
        else
            test_fail "VPC Flow Logs CloudWatch group not found: $vpc_flow_log_group"
        fi
    else
        test_warning "VPC Flow Logs not configured"
    fi
}

# Network connectivity tests
validate_network_connectivity() {
    log "Validating network connectivity..."
    
    # Test DNS resolution for internal services
    local splunk_url=$(jq -r '.splunk_web_internal_url.value' "$TERRAFORM_OUTPUTS" | sed 's|http://||')
    local soar_url=$(jq -r '.soar_internal_url.value' "$TERRAFORM_OUTPUTS" | sed 's|https://||')
    
    if [[ "$splunk_url" != "null" && -n "$splunk_url" ]]; then
        if nslookup "$splunk_url" &>/dev/null; then
            test_pass "Splunk internal DNS resolution works: $splunk_url"
        else
            test_warning "Splunk internal DNS resolution failed: $splunk_url"
        fi
    fi
    
    if [[ "$soar_url" != "null" && -n "$soar_url" ]]; then
        if nslookup "$soar_url" &>/dev/null; then
            test_pass "SOAR internal DNS resolution works: $soar_url"
        else
            test_warning "SOAR internal DNS resolution failed: $soar_url"
        fi
    fi
}

# Generate validation summary
generate_summary() {
    log "Generating validation summary..."
    
    local success_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    fi
    
    cat << EOF | tee -a "$LOG_FILE"

========================================
INFRASTRUCTURE VALIDATION SUMMARY
========================================
Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $success_rate%

EOF

    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✅ All infrastructure validation tests passed!${NC}" | tee -a "$LOG_FILE"
        return 0
    else
        echo -e "${RED}❌ $FAILED_TESTS infrastructure validation tests failed${NC}" | tee -a "$LOG_FILE"
        return 1
    fi
}

# Main validation function
main() {
    log "Starting infrastructure validation..."
    
    # Initialize log file
    echo "Infrastructure Validation Report - $(date)" > "$LOG_FILE"
    echo "================================================" >> "$LOG_FILE"
    
    # Run validation tests
    check_terraform_outputs || exit 1
    validate_vpc
    validate_security_groups
    validate_ec2_instances
    validate_load_balancers
    validate_s3_buckets
    validate_iam_roles
    validate_dns
    validate_monitoring
    validate_network_connectivity
    
    # Generate summary
    generate_summary
}

# Run main function
main "$@"
