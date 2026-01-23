# Vulnerable Terraform configuration for testing Checkov
# Contains intentional security misconfigurations

# Vulnerable: S3 bucket without encryption (Checkov CKV_AWS_19)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read"  # Vulnerable: Public read access (Checkov CKV_AWS_20)

  # Missing: encryption configuration
  # Missing: versioning
  # Missing: logging
}

# Vulnerable: Security group with overly permissive rules (Checkov CKV_AWS_23)
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-security-group"
  description = "Vulnerable security group"

  ingress {
    description = "Allow all inbound traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Vulnerable: Open to the world (Checkov CKV_AWS_260)
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Vulnerable: SSH open to internet (Checkov CKV_AWS_24)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerable: RDS without encryption (Checkov CKV_AWS_16)
resource "aws_db_instance" "vulnerable_rds" {
  allocated_storage    = 20
  engine              = "postgres"
  instance_class      = "db.t2.micro"
  name                = "vulnerabledb"
  username            = "admin"
  password            = "Password123"  # Vulnerable: Hardcoded password (Checkov CKV_AWS_161)
  skip_final_snapshot = true

  # Missing: storage_encrypted = true (Checkov CKV_AWS_16)
  # Missing: backup_retention_period
  # Missing: multi_az = true
  publicly_accessible = true  # Vulnerable: RDS publicly accessible (Checkov CKV_AWS_17)
}

# Vulnerable: EC2 instance with IMDSv1 (Checkov CKV_AWS_79)
resource "aws_instance" "vulnerable_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Missing: metadata_options for IMDSv2
  # Missing: monitoring = true
  # Missing: ebs_optimized = true

  user_data = <<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
              export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              EOF  # Vulnerable: Hardcoded credentials (TruffleHog)
}

# Vulnerable: EBS volume without encryption (Checkov CKV_AWS_3)
resource "aws_ebs_volume" "vulnerable_ebs" {
  availability_zone = "us-west-2a"
  size             = 40

  # Missing: encrypted = true (Checkov CKV_AWS_3)
  # Missing: kms_key_id
}

# Vulnerable: IAM policy with wildcard actions (Checkov CKV_AWS_63)
resource "aws_iam_policy" "vulnerable_policy" {
  name = "vulnerable-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"  # Vulnerable: Wildcard permission (Checkov CKV_AWS_63)
        Effect   = "Allow"
        Resource = "*"  # Vulnerable: All resources (Checkov CKV_AWS_108)
      },
    ]
  })
}

# Vulnerable: CloudTrail without encryption (Checkov CKV_AWS_35)
resource "aws_cloudtrail" "vulnerable_trail" {
  name                          = "vulnerable-trail"
  s3_bucket_name               = aws_s3_bucket.vulnerable_bucket.id
  include_global_service_events = true

  # Missing: kms_key_id (Checkov CKV_AWS_35)
  # Missing: enable_log_file_validation = true (Checkov CKV_AWS_36)
  # Missing: is_multi_region_trail = true (Checkov CKV_AWS_67)
}

# Vulnerable: ALB without access logs (Checkov CKV_AWS_91)
resource "aws_lb" "vulnerable_alb" {
  name               = "vulnerable-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]

  # Missing: access_logs configuration (Checkov CKV_AWS_91)
  # Missing: drop_invalid_header_fields = true (Checkov CKV_AWS_131)
}
