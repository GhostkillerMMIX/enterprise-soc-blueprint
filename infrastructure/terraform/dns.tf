# Route53 Private Hosted Zone
resource "aws_route53_zone" "private" {
  name = "${var.project_name}.local"

  vpc {
    vpc_id = aws_vpc.soc_vpc.id
  }

  tags = {
    Name        = "${var.project_name}-private-zone"
    Environment = var.environment
  }
}

# Route53 Resolver Rules for DNS forwarding (optional)
resource "aws_route53_resolver_rule" "forward_dns" {
  count = length(var.allowed_cidr_blocks) > 0 ? 1 : 0

  domain_name          = "${var.project_name}.local"
  name                 = "${var.project_name}-dns-forward"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.inbound[0].id

  target_ip {
    ip   = "8.8.8.8"
    port = 53
  }

  target_ip {
    ip   = "8.8.4.4"
    port = 53
  }

  tags = {
    Name = "${var.project_name}-dns-forward"
  }
}

# Route53 Resolver Endpoint for inbound queries
resource "aws_route53_resolver_endpoint" "inbound" {
  count = length(var.allowed_cidr_blocks) > 0 ? 1 : 0

  name      = "${var.project_name}-inbound-resolver"
  direction = "INBOUND"

  security_group_ids = [aws_security_group.dns_resolver[0].id]

  ip_address {
    subnet_id = aws_subnet.private[0].id
  }

  ip_address {
    subnet_id = aws_subnet.private[1].id
  }

  tags = {
    Name = "${var.project_name}-inbound-resolver"
  }
}

# Security Group for DNS Resolver
resource "aws_security_group" "dns_resolver" {
  count = length(var.allowed_cidr_blocks) > 0 ? 1 : 0

  name        = "${var.project_name}-dns-resolver"
  description = "Security group for Route53 resolver"
  vpc_id      = aws_vpc.soc_vpc.id

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-dns-resolver-sg"
  }
}

# Additional DNS records for services
resource "aws_route53_record" "cluster_master" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "cluster-master"
  type    = "A"
  ttl     = 300

  # Point to the first indexer for now - in production, this would be a dedicated cluster master
  records = ["10.0.1.10"]  # This should be dynamically assigned
}

resource "aws_route53_record" "deployment_server" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "deployment-server"
  type    = "A"
  ttl     = 300

  # Point to the first search head for now - in production, this would be a dedicated deployment server
  records = ["10.0.1.20"]  # This should be dynamically assigned
}

resource "aws_route53_record" "license_master" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "license-master"
  type    = "A"
  ttl     = 300

  # Point to the first search head for now - in production, this would be a dedicated license master
  records = ["10.0.1.20"]  # This should be dynamically assigned
}

# Wildcard record for dynamic services
resource "aws_route53_record" "wildcard" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "*.${var.project_name}.local"
  type    = "A"
  ttl     = 300

  # Point to load balancer
  records = [aws_lb.splunk_web.dns_name]
}
