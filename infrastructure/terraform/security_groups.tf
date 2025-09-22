# Security Group for Splunk Indexers
resource "aws_security_group" "splunk_indexer" {
  name        = "${var.project_name}-splunk-indexer"
  description = "Security group for Splunk indexers"
  vpc_id      = aws_vpc.soc_vpc.id

  # Splunk Web (8000)
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.splunk_search_head.id]
  }

  # Splunk Management (8089)
  ingress {
    from_port       = 8089
    to_port         = 8089
    protocol        = "tcp"
    security_groups = [aws_security_group.splunk_search_head.id, aws_security_group.splunk_heavy_forwarder.id]
  }

  # Splunk Indexer Replication (9887)
  ingress {
    from_port = 9887
    to_port   = 9887
    protocol  = "tcp"
    self      = true
  }

  # Splunk Forwarder Data (9997)
  ingress {
    from_port       = 9997
    to_port         = 9997
    protocol        = "tcp"
    security_groups = [aws_security_group.splunk_heavy_forwarder.id]
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-splunk-indexer-sg"
  }
}

# Security Group for Splunk Search Heads
resource "aws_security_group" "splunk_search_head" {
  name        = "${var.project_name}-splunk-search-head"
  description = "Security group for Splunk search heads"
  vpc_id      = aws_vpc.soc_vpc.id

  # Splunk Web (8000) - User access
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Splunk Web (8000) - Load balancer
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Splunk Management (8089)
  ingress {
    from_port = 8089
    to_port   = 8089
    protocol  = "tcp"
    self      = true
  }

  # Search Head Clustering (8191)
  ingress {
    from_port = 8191
    to_port   = 8191
    protocol  = "tcp"
    self      = true
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-splunk-search-head-sg"
  }
}

# Security Group for Splunk Heavy Forwarders
resource "aws_security_group" "splunk_heavy_forwarder" {
  name        = "${var.project_name}-splunk-heavy-forwarder"
  description = "Security group for Splunk heavy forwarders"
  vpc_id      = aws_vpc.soc_vpc.id

  # Splunk Management (8089)
  ingress {
    from_port       = 8089
    to_port         = 8089
    protocol        = "tcp"
    security_groups = [aws_security_group.splunk_search_head.id]
  }

  # Syslog (514)
  ingress {
    from_port   = 514
    to_port     = 514
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    from_port   = 514
    to_port     = 514
    protocol    = "udp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Splunk HEC (8088)
  ingress {
    from_port   = 8088
    to_port     = 8088
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-splunk-heavy-forwarder-sg"
  }
}

# Security Group for SOAR Platform
resource "aws_security_group" "soar" {
  name        = "${var.project_name}-soar"
  description = "Security group for SOAR platform"
  vpc_id      = aws_vpc.soc_vpc.id

  # HTTPS (443) - Web interface
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTP (80) - Redirect to HTTPS
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-soar-sg"
  }
}

# Security Group for Zeek Sensors
resource "aws_security_group" "zeek" {
  name        = "${var.project_name}-zeek"
  description = "Security group for Zeek network sensors"
  vpc_id      = aws_vpc.soc_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Zeek management interface (if applicable)
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-zeek-sg"
  }
}

# Security Group for Application Load Balancer
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.soc_vpc.id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTPS
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# Security Group for RDS (if using database)
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.soc_vpc.id

  # MySQL/Aurora
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [
      aws_security_group.splunk_indexer.id,
      aws_security_group.splunk_search_head.id,
      aws_security_group.soar.id
    ]
  }

  # PostgreSQL
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [
      aws_security_group.splunk_indexer.id,
      aws_security_group.splunk_search_head.id,
      aws_security_group.soar.id
    ]
  }

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}

# Security Group for ElastiCache (Redis/Memcached)
resource "aws_security_group" "elasticache" {
  name        = "${var.project_name}-elasticache"
  description = "Security group for ElastiCache"
  vpc_id      = aws_vpc.soc_vpc.id

  # Redis
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [
      aws_security_group.splunk_search_head.id,
      aws_security_group.soar.id
    ]
  }

  # Memcached
  ingress {
    from_port       = 11211
    to_port         = 11211
    protocol        = "tcp"
    security_groups = [
      aws_security_group.splunk_search_head.id,
      aws_security_group.soar.id
    ]
  }

  tags = {
    Name = "${var.project_name}-elasticache-sg"
  }
}

# Security Group for Kafka (if using)
resource "aws_security_group" "kafka" {
  name        = "${var.project_name}-kafka"
  description = "Security group for Kafka cluster"
  vpc_id      = aws_vpc.soc_vpc.id

  # Kafka broker communication
  ingress {
    from_port = 9092
    to_port   = 9092
    protocol  = "tcp"
    security_groups = [
      aws_security_group.splunk_heavy_forwarder.id,
      aws_security_group.splunk_indexer.id
    ]
  }

  # Kafka inter-broker communication
  ingress {
    from_port = 9093
    to_port   = 9093
    protocol  = "tcp"
    self      = true
  }

  # Zookeeper
  ingress {
    from_port = 2181
    to_port   = 2181
    protocol  = "tcp"
    self      = true
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-kafka-sg"
  }
}
