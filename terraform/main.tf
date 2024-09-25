# # GDPR Compliant AWS VPC Environment
#
# # The General Data Protection Regulation (GDPR) is a European Union regulation that mandates stringent data
# # protection and privacy requirements for all companies handling EU citizens' data. To ensure GDPR compliance
# # in an AWS environment, the following aspects are essential:
#
# # Data Encryption - Both at rest and in transit, data should be
# # encrypted using strong encryption methods (e.g., AES-256).
#
# # Access Controls - Strict IAM roles and policies must be enforced
# # to ensure only authorized entities can access personal data.
#
# # Auditability - Enable logging and monitoring to ensure that all
# # access to personal data is auditable.
#
# # Data Residency - Ensure that data is stored in compliant regions
# # (e.g., within the EU).
#
# # Data Minimization - Ensure that only necessary data is collected
# # and processed.
#
# # Incident Response - Set up mechanisms for data breach detection
# # and notification.
#
# # ---------------------------------------------------------------------------------------------------------------------
# #### AWS Provider Configuration ####
# # ---------------------------------------------------------------------------------------------------------------------
#
provider "aws" {
  region     = "eu-west-1"

  profile = "default"
#   access_key = ""
#   secret_key = ""
}
#
# ---------------------------------------------------------------------------------------------------------------------
#### Networking Resources ####
# ---------------------------------------------------------------------------------------------------------------------

## VPC for isolation ##
resource "aws_vpc" "gdpr_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "gdpr_compliant"
  }
}

## Subnet for resources ##
resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.gdpr_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-west-1a"
  tags = {
    Name = "public_subnet"
  }
}
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.gdpr_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-west-1b"
  tags = {
    Name = "private_subnet"
  }
}

## RDS Subnet Group for PostgreSQL ##
resource "aws_db_subnet_group" "gdpr_db_subnet_group" {
  name       = "gdpr-db-subnet-group"
  subnet_ids = [
    aws_subnet.public_subnet.id,
    aws_subnet.private_subnet.id
  ]

  tags = {
    Name = "gdpr_db_subnet_group"
  }
}

## Internet Gateway ##
resource "aws_internet_gateway" "gdpr_igw" {
  vpc_id = aws_vpc.gdpr_vpc.id
  tags = {
    Name = "gdpr_igw"
  }
}

## Route Table & Associate Subnet with Route Table ##
resource "aws_route_table" "gdpr_rt" {
  vpc_id = aws_vpc.gdpr_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gdpr_igw.id
  }
  tags = {
    Name = "gdpr_rt"
  }
}
resource "aws_route_table_association" "public_gdpr_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.gdpr_rt.id
}
resource "aws_route_table_association" "private_gdpr_rta" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.gdpr_rt.id
}

# ---------------------------------------------------------------------------------------------------------------------
#### Encryption and Data Protection ####
# ---------------------------------------------------------------------------------------------------------------------

## KMS (key management service) Key for Encryption ##
resource "aws_kms_key" "gdpr_key" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Allow root user of account full access to the key
      {
        Sid       = "AllowRootUserFullAccess",
        Effect    = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action    = "kms:*",
        Resource  = "*"
      },
      # Allow AWS Config to use the KMS key
      {
        Sid       = "AllowAWSConfig",
        Effect    = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        Resource = "*"
      }
    ]
  })
}


## S3 Bucket & S3 Bucket for Logs ##
resource "aws_s3_bucket" "gdpr_s3_bucket" {
  bucket = "gdpr-compliant-bucket-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "gdpr_s3_bucket"
    Environment = "production"
  }
}
resource "aws_s3_bucket" "gdpr_s3_log_bucket" {
  bucket = "gdpr-log-bucket-${random_string.bucket_suffix.result}"
  tags = {
    Name = "gdpr_s3_log_bucket"
    Environment = "production"
  }
}

## S3 Bucket & S3 Bucket for Logs with Encryption ##
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_s3_gdpr_s3_bucket" {
  bucket = aws_s3_bucket.gdpr_s3_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.gdpr_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_s3_gdpr_s3_log_bucket" {
  bucket = aws_s3_bucket.gdpr_s3_log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.gdpr_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Security Controls ####
# ---------------------------------------------------------------------------------------------------------------------

## Security Group for EC2 Instance and RDS ##
resource "aws_security_group" "gdpr_web_sg" {
  name = "gdpr_web_sg"
  vpc_id = aws_vpc.gdpr_vpc.id

  # Allow HTTPS access from specific trusted IPs
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
    description = "Allow HTTPS from trusted IP range"
  }

  # Restrict SSH access to a specific trusted IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
    description = "Allow SSH from trusted IP range"
  }

  # Allow outbound internet traffic (necessary for updates, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "gdpr_web_sg"
  }
}

## IAM Role for EC2 with Logging Permissions ##
resource "aws_iam_role" "gdpr_ec2_role" {
  name = "gdpr_ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

## IAM Role Policy for S3 Access ##
resource "aws_iam_role_policy" "gdpr_s3_policy" {
  name = "gdpr_s3_policy"
  role = aws_iam_role.gdpr_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.gdpr_s3_bucket.arn,
          "${aws_s3_bucket.gdpr_s3_bucket.arn}/*",
        ]
      },
    ]
  })
}
resource "aws_s3_bucket_policy" "gdpr_s3_log_bucket_policy" {
  bucket = aws_s3_bucket.gdpr_s3_log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # CloudTrail permissions
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.gdpr_s3_log_bucket.arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ],
        Resource = "${aws_s3_bucket.gdpr_s3_log_bucket.arn}"
      },

      # AWS Config permissions
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = [
          "s3:PutObject"
        ],
        Resource = "${aws_s3_bucket.gdpr_s3_log_bucket.arn}/*",
      },
      # AWS Config permissions
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ],
        Resource = "${aws_s3_bucket.gdpr_s3_log_bucket.arn}"
      },
      # AWS Root User permissions
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "s3:GetBucketAcl",
        Resource = "${aws_s3_bucket.gdpr_s3_log_bucket.arn}"
      }
    ]
  })
}

## IAM Instance Profile for EC2 ##
resource "aws_iam_instance_profile" "gdpr_ec2_profile" {
  name = "gdpr_ec2_profile"
  role = aws_iam_role.gdpr_ec2_role.name
}

# ---------------------------------------------------------------------------------------------------------------------
#### Compute Resources ####
# ---------------------------------------------------------------------------------------------------------------------

## EC2 Instance ##
resource "aws_instance" "gdpr_web_server" {
  ami           = "ami-03cc8375791cb8bcf"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_subnet.id
  iam_instance_profile = aws_iam_instance_profile.gdpr_ec2_profile.name
  monitoring = true

  # Attach security group
  vpc_security_group_ids = [aws_security_group.gdpr_web_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    sudo apt-get update
    sudo apt-get install -y nginx
    echo "Hello, GDPR Compliant Server... Your are now Coldchain Secure!" > /var/www/html/index.html
    EOF

  tags = {
    Name = "gdpr_web_server"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Database Configuration ####
# ---------------------------------------------------------------------------------------------------------------------

# RDS PostgreSQL Instance
resource "aws_db_instance" "gdpr_db" {
  identifier = "gdpr-db"
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  db_name              = "gdpr_db"
  username             = "postgres"
  password             = "postgres"
  parameter_group_name = "default.postgres15"
  db_subnet_group_name = aws_db_subnet_group.gdpr_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.gdpr_web_sg.id]
  multi_az             = true
  publicly_accessible  = false
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.gdpr_key.arn
  backup_retention_period = 7
  delete_automated_backups = true
  skip_final_snapshot = true

  tags = {
    Name = "gdpr_db"
    Environment = "production"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Monitoring and Logging ####
# ---------------------------------------------------------------------------------------------------------------------

## Enable CloudTrail for logging ##
resource "aws_cloudtrail" "gdpr_cloudtrail" {
  name                          = "gdpr-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.gdpr_s3_log_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::${aws_s3_bucket.gdpr_s3_log_bucket.id}/*"
      ]
    }
  }
}

## AWS Config Delivery Channel ##
resource "aws_config_delivery_channel" "gdpr_log_delivery" {
  name           = "gdpr-log-delivery"
  s3_bucket_name = aws_s3_bucket.gdpr_s3_log_bucket.bucket
  s3_key_prefix   = "aws-config-logs"
  s3_kms_key_arn = aws_kms_key.gdpr_key.arn
}




# local Vars
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}
data "aws_caller_identity" "current" {}
