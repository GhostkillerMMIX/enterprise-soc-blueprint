# Launch Template for SOAR Platform
resource "aws_launch_template" "soar" {
  name_prefix   = "${var.project_name}-soar-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.soar_instance_type
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.soar.id]

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
      volume_size           = 500
      iops                  = 3000
      throughput            = 125
      delete_on_termination = false
      encrypted             = true
    }
  }

  # IAM instance profile
  iam_instance_profile {
    name = aws_iam_instance_profile.soar.name
  }

  # User data script
  user_data = base64encode(templatefile("${path.module}/../scripts/soar-userdata.sh", {
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

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-soar"
      Role = "soar-platform"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.project_name}-soar-volume"
      Role = "soar-platform"
    }
  }
}

# Auto Scaling Group for SOAR (typically single instance)
resource "aws_autoscaling_group" "soar" {
  name                = "${var.project_name}-soar-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.soar.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.soar_instance_count
  max_size         = var.soar_instance_count
  desired_capacity = var.soar_instance_count

  launch_template {
    id      = aws_launch_template.soar.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-soar"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "soar-platform"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}

# Application Load Balancer for SOAR
resource "aws_lb" "soar" {
  name               = "${var.project_name}-soar-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.private[*].id

  enable_deletion_protection = false

  tags = {
    Name = "${var.project_name}-soar-alb"
  }
}

# Target Group for SOAR
resource "aws_lb_target_group" "soar" {
  name     = "${var.project_name}-soar"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.soc_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 30
    path                = "/health"
    matcher             = "200"
    port                = "traffic-port"
    protocol            = "HTTPS"
  }

  tags = {
    Name = "${var.project_name}-soar-tg"
  }
}

# ALB Listener for SOAR (HTTPS)
resource "aws_lb_listener" "soar_https" {
  load_balancer_arn = aws_lb.soar.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.soar.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.soar.arn
  }
}

# ALB Listener for SOAR (HTTP redirect to HTTPS)
resource "aws_lb_listener" "soar_http" {
  load_balancer_arn = aws_lb.soar.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Self-signed certificate for SOAR (replace with real cert in production)
resource "tls_private_key" "soar" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "soar" {
  private_key_pem = tls_private_key.soar.private_key_pem

  subject {
    common_name  = "soar.${var.project_name}.local"
    organization = "SOC Team"
  }

  validity_period_hours = 8760 # 1 year

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# ACM Certificate for SOAR
resource "aws_acm_certificate" "soar" {
  private_key      = tls_private_key.soar.private_key_pem
  certificate_body = tls_self_signed_cert.soar.cert_pem

  tags = {
    Name = "${var.project_name}-soar-cert"
  }
}

# IAM Role for SOAR
resource "aws_iam_role" "soar" {
  name = "${var.project_name}-soar-role"

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

# IAM Policy for SOAR
resource "aws_iam_role_policy" "soar" {
  name = "${var.project_name}-soar-policy"
  role = aws_iam_role.soar.id

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
          aws_s3_bucket.soar_playbooks.arn,
          "${aws_s3_bucket.soar_playbooks.arn}/*"
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
        Resource = aws_secretsmanager_secret.soar_secrets.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:StopInstances",
          "ec2:StartInstances",
          "ec2:RebootInstances",
          "ec2:CreateTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Region" = var.aws_region
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.alerts[0].arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:*:function:${var.project_name}-*"
      }
    ]
  })
}

# IAM Instance Profile for SOAR
resource "aws_iam_instance_profile" "soar" {
  name = "${var.project_name}-soar-profile"
  role = aws_iam_role.soar.name
}

# CloudWatch Alarms for SOAR Health
resource "aws_cloudwatch_metric_alarm" "soar_cpu_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-soar-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors SOAR cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.soar.name
  }
}

resource "aws_cloudwatch_metric_alarm" "soar_memory_high" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-soar-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "CWAgent"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors SOAR memory utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.soar.name
  }
}

# Route53 Record for SOAR
resource "aws_route53_record" "soar" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "soar"
  type    = "A"

  alias {
    name                   = aws_lb.soar.dns_name
    zone_id                = aws_lb.soar.zone_id
    evaluate_target_health = true
  }
}
