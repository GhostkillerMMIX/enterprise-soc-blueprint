# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  count = var.enable_monitoring ? 1 : 0

  name = "${var.project_name}-alerts"

  tags = {
    Name        = "${var.project_name}-alerts"
    Environment = var.environment
  }
}

# SNS Topic Subscription for Email
resource "aws_sns_topic_subscription" "email_alerts" {
  count = var.enable_monitoring && length(var.email_notifications) > 0 ? length(var.email_notifications) : 0

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.email_notifications[count.index]
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "alerts" {
  count = var.enable_monitoring ? 1 : 0

  arn = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts[0].arn
      }
    ]
  })
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "soc_overview" {
  count = var.enable_monitoring ? 1 : 0

  dashboard_name = "${var.project_name}-soc-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.splunk_indexer.name],
            [".", ".", ".", aws_autoscaling_group.splunk_search_head.name],
            [".", ".", ".", aws_autoscaling_group.soar.name],
            [".", ".", ".", aws_autoscaling_group.zeek.name]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "NetworkIn", "AutoScalingGroupName", aws_autoscaling_group.splunk_indexer.name],
            [".", "NetworkOut", ".", "."],
            [".", "NetworkIn", ".", aws_autoscaling_group.splunk_search_head.name],
            [".", "NetworkOut", ".", "."]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Network Traffic"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.splunk_web.arn_suffix],
            [".", "RequestCount", ".", "."],
            [".", "TargetResponseTime", ".", aws_lb.soar.arn_suffix],
            [".", "RequestCount", ".", "."]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Load Balancer Metrics"
        }
      }
    ]
  })
}

# CloudWatch Log Groups for Application Logs
resource "aws_cloudwatch_log_group" "splunk_search_head" {
  count = var.enable_monitoring ? 1 : 0

  name              = "/aws/ec2/${var.project_name}/search-head"
  retention_in_days = var.backup_retention_days

  tags = {
    Name        = "${var.project_name}-search-head-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "soar" {
  count = var.enable_monitoring ? 1 : 0

  name              = "/aws/ec2/${var.project_name}/soar"
  retention_in_days = var.backup_retention_days

  tags = {
    Name        = "${var.project_name}-soar-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "zeek" {
  count = var.enable_monitoring ? 1 : 0

  name              = "/aws/ec2/${var.project_name}/zeek"
  retention_in_days = var.backup_retention_days

  tags = {
    Name        = "${var.project_name}-zeek-logs"
    Environment = var.environment
  }
}

# CloudWatch Composite Alarms
resource "aws_cloudwatch_composite_alarm" "soc_health" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name        = "${var.project_name}-soc-health"
  alarm_description = "Overall SOC infrastructure health"

  alarm_rule = join(" OR ", [
    "ALARM(${aws_cloudwatch_metric_alarm.indexer_cpu_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.indexer_disk_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.search_head_cpu_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.search_head_memory_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.soar_cpu_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.soar_memory_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.zeek_cpu_high[0].alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.zeek_disk_high[0].alarm_name})"
  ])

  alarm_actions = [aws_sns_topic.alerts[0].arn]
  ok_actions    = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "${var.project_name}-soc-health"
    Environment = var.environment
  }
}

# Custom CloudWatch Metrics for SOC KPIs
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  count = var.enable_monitoring ? 1 : 0

  name           = "${var.project_name}-security-events"
  log_group_name = aws_cloudwatch_log_group.splunk_search_head[0].name
  pattern        = "[timestamp, level=\"ERROR\", message*=\"security\"]"

  metric_transformation {
    name      = "SecurityEvents"
    namespace = "${var.project_name}/SOC"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "failed_logins" {
  count = var.enable_monitoring ? 1 : 0

  name           = "${var.project_name}-failed-logins"
  log_group_name = aws_cloudwatch_log_group.splunk_search_head[0].name
  pattern        = "[timestamp, level, message*=\"failed login\"]"

  metric_transformation {
    name      = "FailedLogins"
    namespace = "${var.project_name}/SOC"
    value     = "1"
  }
}

# CloudWatch Alarms for SOC KPIs
resource "aws_cloudwatch_metric_alarm" "high_security_events" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-high-security-events"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "SecurityEvents"
  namespace           = "${var.project_name}/SOC"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "High number of security events detected"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "high_failed_logins" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-high-failed-logins"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FailedLogins"
  namespace           = "${var.project_name}/SOC"
  period              = "300"
  statistic           = "Sum"
  threshold           = "20"
  alarm_description   = "High number of failed login attempts"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  treat_missing_data = "notBreaching"
}

# EventBridge Rules for Automation
resource "aws_cloudwatch_event_rule" "instance_state_change" {
  count = var.enable_monitoring ? 1 : 0

  name        = "${var.project_name}-instance-state-change"
  description = "Capture instance state changes"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification"]
    detail = {
      state = ["stopped", "terminated", "stopping", "terminating"]
    }
  })
}

# EventBridge Target for Instance State Changes
resource "aws_cloudwatch_event_target" "sns_target" {
  count = var.enable_monitoring ? 1 : 0

  rule      = aws_cloudwatch_event_rule.instance_state_change[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts[0].arn
}

# Lambda function for custom metrics (optional)
resource "aws_lambda_function" "custom_metrics" {
  count = var.enable_monitoring ? 1 : 0

  filename         = "${path.module}/lambda/custom_metrics.zip"
  function_name    = "${var.project_name}-custom-metrics"
  role            = aws_iam_role.lambda_metrics[0].arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 60

  environment {
    variables = {
      PROJECT_NAME = var.project_name
      ENVIRONMENT  = var.environment
    }
  }

  tags = {
    Name        = "${var.project_name}-custom-metrics"
    Environment = var.environment
  }
}

# IAM Role for Lambda Custom Metrics
resource "aws_iam_role" "lambda_metrics" {
  count = var.enable_monitoring ? 1 : 0

  name = "${var.project_name}-lambda-metrics-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda Custom Metrics
resource "aws_iam_role_policy" "lambda_metrics" {
  count = var.enable_monitoring ? 1 : 0

  name = "${var.project_name}-lambda-metrics-policy"
  role = aws_iam_role.lambda_metrics[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Event Rule to trigger Lambda
resource "aws_cloudwatch_event_rule" "custom_metrics_schedule" {
  count = var.enable_monitoring ? 1 : 0

  name                = "${var.project_name}-custom-metrics-schedule"
  description         = "Trigger custom metrics collection"
  schedule_expression = "rate(5 minutes)"
}

# CloudWatch Event Target for Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  count = var.enable_monitoring ? 1 : 0

  rule      = aws_cloudwatch_event_rule.custom_metrics_schedule[0].name
  target_id = "CustomMetricsLambda"
  arn       = aws_lambda_function.custom_metrics[0].arn
}

# Lambda Permission for CloudWatch Events
resource "aws_lambda_permission" "allow_cloudwatch" {
  count = var.enable_monitoring ? 1 : 0

  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.custom_metrics[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.custom_metrics_schedule[0].arn
}
