# Data source for latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Launch Template for Splunk Indexers
resource "aws_launch_template" "splunk_indexer" {
  name_prefix   = "${var.project_name}-indexer-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.splunk_indexer_instance_type
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.splunk_indexer.id]

  # EBS optimized for better storage performance
  ebs_optimized = true

  # Block device mappings
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = 100
      delete_on_termination = true
      encrypted             = true
    }
  }

  # Hot storage volume
  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      volume_type           = "gp3"
      volume_size           = var.indexer_hot_storage_size
      iops                  = 3000
      throughput            = 125
      delete_on_termination = false
      encrypted             = true
    }
  }

  # Warm storage volume
  block_device_mappings {
    device_name = "/dev/xvdc"
    ebs {
      volume_type           = "gp3"
      volume_size           = var.indexer_warm_storage_size
      delete_on_termination = false
      encrypted             = true
    }
  }

  # IAM instance profile
  iam_instance_profile {
    name = aws_iam_instance_profile.splunk_indexer.name
  }

  # User data script for initial setup
  user_data = base64encode(templatefile("${path.module}/../scripts/indexer-userdata.sh", {
    splunk_admin_password = var.splunk_admin_password
    environment          = var.environment
    project_name         = var.project_name
  }))

  # Monitoring
  monitoring {
    enabled = var.enable_monitoring
  }

  # Metadata options (IMDSv2)
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-indexer"
      Role = "splunk-indexer"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.project_name}-indexer-volume"
      Role = "splunk-indexer"
    }
  }
}

# Auto Scaling Group for Splunk Indexers
resource "aws_autoscaling_group" "splunk_indexer" {
  name                = "${var.project_name}-indexer-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = []
  health_check_type   = "EC2"
  health_check_grace_period = 300

  min_size         = var.splunk_indexer_count
  max_size         = var.splunk_indexer_count + 2
  desired_capacity = var.splunk_indexer_count

  launch_template {
    id      = aws_launch_template.splunk_indexer.id
    version = "$Latest"
  }

  # Instance refresh for rolling updates
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-indexer"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "splunk-indexer"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  # Lifecycle hooks for graceful shutdown
  initial_lifecycle_hook {
    name                 = "indexer-termination-hook"
    default_result       = "ABANDON"
    heartbeat_timeout    = 300
    lifecycle_transition = "autoscaling:EC2_INSTANCE_TERMINATING"
  }
}

# IAM Role for Splunk Indexers
resource "aws_iam_role" "splunk_indexer" {
  name = "${var.project_name}-indexer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Splunk Indexers
resource "aws_iam_role_policy" "splunk_indexer" {
  name = "${var.project_name}-indexer-policy"
  role = aws_iam_role.splunk_indexer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.splunk_cold_storage.arn,
          "${aws_s3_bucket.splunk_cold_storage.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.splunk_secrets.arn
      }
    ]
  })
}

# IAM Instance Profile for Splunk Indexers
resource "aws_iam_instance_profile" "splunk_indexer" {
  name = "${var.project_name}-indexer-profile"
  role = aws_iam_role.splunk_indexer.name
}

# CloudWatch Log Group for Splunk Indexers
resource "aws_cloudwatch_log_group" "splunk_indexer" {
  count = var.enable_monitoring ? 1 : 0

  name              = "/aws/ec2/${var.project_name}/indexer"
  retention_in_days = var.backup_retention_days

  tags = {
    Name = "${var.project_name}-indexer-logs"
  }
}

# CloudWatch Alarms for Indexer Health
resource "aws_cloudwatch_metric_alarm" "indexer_cpu_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-indexer-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors indexer cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.splunk_indexer.name
  }
}

resource "aws_cloudwatch_metric_alarm" "indexer_disk_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-indexer-disk-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DiskSpaceUtilization"
  namespace           = "CWAgent"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors indexer disk utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.splunk_indexer.name
    Device               = "/dev/xvdb"
    Fstype              = "xfs"
    MountPath           = "/opt/splunk/var/lib/splunk"
  }
}
