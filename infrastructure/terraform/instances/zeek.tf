# Launch Template for Zeek Sensors
resource "aws_launch_template" "zeek" {
  name_prefix   = "${var.project_name}-zeek-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.zeek_instance_type
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.zeek.id]

  # EBS optimized
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

  # Storage for packet captures and logs
  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      volume_type           = "gp3"
      volume_size           = 1000
      iops                  = 3000
      throughput            = 250
      delete_on_termination = false
      encrypted             = true
    }
  }

  # IAM instance profile
  iam_instance_profile {
    name = aws_iam_instance_profile.zeek.name
  }

  # User data script
  user_data = base64encode(templatefile("${path.module}/../scripts/zeek-userdata.sh", {
    environment  = var.environment
    project_name = var.project_name
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

  # Network interfaces for traffic mirroring
  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    device_index                = 0
    security_groups            = [aws_security_group.zeek.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-zeek"
      Role = "zeek-sensor"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.project_name}-zeek-volume"
      Role = "zeek-sensor"
    }
  }
}

# Auto Scaling Group for Zeek Sensors
resource "aws_autoscaling_group" "zeek" {
  name                = "${var.project_name}-zeek-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  health_check_type   = "EC2"
  health_check_grace_period = 300

  min_size         = var.zeek_instance_count
  max_size         = var.zeek_instance_count + 1
  desired_capacity = var.zeek_instance_count

  launch_template {
    id      = aws_launch_template.zeek.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-zeek"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "zeek-sensor"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}

# VPC Traffic Mirroring Target
resource "aws_ec2_traffic_mirror_target" "zeek" {
  description          = "Traffic mirror target for Zeek sensors"
  network_interface_id = aws_network_interface.zeek_mirror.id

  tags = {
    Name = "${var.project_name}-zeek-mirror-target"
  }
}

# Dedicated network interface for traffic mirroring
resource "aws_network_interface" "zeek_mirror" {
  subnet_id       = aws_subnet.private[0].id
  security_groups = [aws_security_group.zeek.id]

  tags = {
    Name = "${var.project_name}-zeek-mirror-interface"
  }
}

# Traffic Mirror Filter
resource "aws_ec2_traffic_mirror_filter" "zeek" {
  description      = "Traffic mirror filter for Zeek"
  network_services = ["amazon-dns"]

  tags = {
    Name = "${var.project_name}-zeek-mirror-filter"
  }
}

# Ingress rule for HTTP traffic
resource "aws_ec2_traffic_mirror_filter_rule" "http_ingress" {
  description              = "HTTP ingress traffic"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.zeek.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_action             = "accept"
  rule_number             = 100
  traffic_direction       = "ingress"
  protocol                = 6  # TCP

  destination_port_range {
    from_port = 80
    to_port   = 80
  }
}

# Ingress rule for HTTPS traffic
resource "aws_ec2_traffic_mirror_filter_rule" "https_ingress" {
  description              = "HTTPS ingress traffic"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.zeek.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_action             = "accept"
  rule_number             = 101
  traffic_direction       = "ingress"
  protocol                = 6  # TCP

  destination_port_range {
    from_port = 443
    to_port   = 443
  }
}

# Egress rule for HTTP traffic
resource "aws_ec2_traffic_mirror_filter_rule" "http_egress" {
  description              = "HTTP egress traffic"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.zeek.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_action             = "accept"
  rule_number             = 200
  traffic_direction       = "egress"
  protocol                = 6  # TCP

  source_port_range {
    from_port = 80
    to_port   = 80
  }
}

# Egress rule for HTTPS traffic
resource "aws_ec2_traffic_mirror_filter_rule" "https_egress" {
  description              = "HTTPS egress traffic"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.zeek.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_action             = "accept"
  rule_number             = 201
  traffic_direction       = "egress"
  protocol                = 6  # TCP

  source_port_range {
    from_port = 443
    to_port   = 443
  }
}

# IAM Role for Zeek
resource "aws_iam_role" "zeek" {
  name = "${var.project_name}-zeek-role"

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

# IAM Policy for Zeek
resource "aws_iam_role_policy" "zeek" {
  name = "${var.project_name}-zeek-policy"
  role = aws_iam_role.zeek.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.zeek_logs.arn,
          "${aws_s3_bucket.zeek_logs.arn}/*"
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
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Instance Profile for Zeek
resource "aws_iam_instance_profile" "zeek" {
  name = "${var.project_name}-zeek-profile"
  role = aws_iam_role.zeek.name
}

# CloudWatch Alarms for Zeek Health
resource "aws_cloudwatch_metric_alarm" "zeek_cpu_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-zeek-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Zeek cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.zeek.name
  }
}

resource "aws_cloudwatch_metric_alarm" "zeek_disk_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-zeek-disk-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DiskSpaceUtilization"
  namespace           = "CWAgent"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors Zeek disk utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.zeek.name
    Device               = "/dev/xvdb"
    Fstype              = "xfs"
    MountPath           = "/opt/zeek/logs"
  }
}

# S3 Bucket for Zeek Logs
resource "aws_s3_bucket" "zeek_logs" {
  bucket = "${var.project_name}-zeek-logs-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-zeek-logs"
    Environment = var.environment
  }
}

# S3 Bucket versioning
resource "aws_s3_bucket_versioning" "zeek_logs" {
  bucket = aws_s3_bucket.zeek_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "zeek_logs" {
  bucket = aws_s3_bucket.zeek_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket lifecycle policy
resource "aws_s3_bucket_lifecycle_configuration" "zeek_logs" {
  bucket = aws_s3_bucket.zeek_logs.id

  rule {
    id     = "zeek_log_lifecycle"
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
      days = 2555  # 7 years
    }
  }
}
