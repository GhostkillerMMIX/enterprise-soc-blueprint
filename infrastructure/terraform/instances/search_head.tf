# Launch Template for Splunk Search Heads
resource "aws_launch_template" "splunk_search_head" {
  name_prefix   = "${var.project_name}-search-head-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.splunk_search_head_instance_type
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.splunk_search_head.id]

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

  # Application storage
  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      volume_type           = "gp3"
      volume_size           = 200
      iops                  = 3000
      throughput            = 125
      delete_on_termination = false
      encrypted             = true
    }
  }

  # IAM instance profile
  iam_instance_profile {
    name = aws_iam_instance_profile.splunk_search_head.name
  }

  # User data script
  user_data = base64encode(templatefile("${path.module}/../scripts/search-head-userdata.sh", {
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
      Name = "${var.project_name}-search-head"
      Role = "splunk-search-head"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.project_name}-search-head-volume"
      Role = "splunk-search-head"
    }
  }
}

# Auto Scaling Group for Search Heads
resource "aws_autoscaling_group" "splunk_search_head" {
  name                = "${var.project_name}-search-head-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.splunk_web.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.splunk_search_head_count
  max_size         = var.splunk_search_head_count + 1
  desired_capacity = var.splunk_search_head_count

  launch_template {
    id      = aws_launch_template.splunk_search_head.id
    version = "$Latest"
  }

  # Instance refresh
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-search-head"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "splunk-search-head"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}

# Application Load Balancer for Search Heads
resource "aws_lb" "splunk_web" {
  name               = "${var.project_name}-splunk-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.private[*].id

  enable_deletion_protection = false

  tags = {
    Name = "${var.project_name}-splunk-alb"
  }
}

# Target Group for Splunk Web
resource "aws_lb_target_group" "splunk_web" {
  name     = "${var.project_name}-splunk-web"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.soc_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/en-US/account/login"
    matcher             = "200"
    port                = "traffic-port"
    protocol            = "HTTP"
  }

  tags = {
    Name = "${var.project_name}-splunk-web-tg"
  }
}

# ALB Listener
resource "aws_lb_listener" "splunk_web" {
  load_balancer_arn = aws_lb.splunk_web.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.splunk_web.arn
  }
}

# IAM Role for Search Heads
resource "aws_iam_role" "splunk_search_head" {
  name = "${var.project_name}-search-head-role"

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

# IAM Policy for Search Heads
resource "aws_iam_role_policy" "splunk_search_head" {
  name = "${var.project_name}-search-head-policy"
  role = aws_iam_role.splunk_search_head.id

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
          aws_s3_bucket.splunk_apps.arn,
          "${aws_s3_bucket.splunk_apps.arn}/*",
          aws_s3_bucket.splunk_lookups.arn,
          "${aws_s3_bucket.splunk_lookups.arn}/*"
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
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Instance Profile for Search Heads
resource "aws_iam_instance_profile" "splunk_search_head" {
  name = "${var.project_name}-search-head-profile"
  role = aws_iam_role.splunk_search_head.name
}

# CloudWatch Alarms for Search Head Health
resource "aws_cloudwatch_metric_alarm" "search_head_cpu_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-search-head-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors search head cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.splunk_search_head.name
  }
}

resource "aws_cloudwatch_metric_alarm" "search_head_memory_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-search-head-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "CWAgent"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors search head memory utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.splunk_search_head.name
  }
}

# Route53 Private Hosted Zone Record for Load Balancer
resource "aws_route53_record" "splunk_web" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "splunk"
  type    = "A"

  alias {
    name                   = aws_lb.splunk_web.dns_name
    zone_id                = aws_lb.splunk_web.zone_id
    evaluate_target_health = true
  }
}
