# GDPR Compliant AWS VPC Environment

# The General Data Protection Regulation (GDPR) is a European Union regulation that mandates stringent data
# protection and privacy requirements for all companies handling EU citizens' data. To ensure GDPR compliance
# in an AWS environment, the following aspects are essential:

# Data Encryption - Both at rest and in transit, data should be
# encrypted using strong encryption methods (e.g., AES-256).

# Access Controls - Strict IAM roles and policies must be enforced
# to ensure only authorized entities can access personal data.

# Auditability - Enable logging and monitoring to ensure that all
# access to personal data is auditable.

# Data Residency - Ensure that data is stored in compliant regions
# (e.g., within the EU).

# Data Minimization - Ensure that only necessary data is collected
# and processed.

# Incident Response - Set up mechanisms for data breach detection
# and notification.

# ---------------------------------------------------------------------------------------------------------------------
#### AWS Provider Configuration ####
# ---------------------------------------------------------------------------------------------------------------------

# Specifies the eu-west-1 region, which is within the European Union, ensuring data residency
# compliance with GDPR. This ensures that all resources, including data, are hosted within the
# EU, adhering to GDPR’s data residency requirements.
provider "aws" {
  region     = "eu-west-1"

  profile = "default"
#   access_key = ""
#   secret_key = ""
}

# ---------------------------------------------------------------------------------------------------------------------
#### Networking Resources ####
# ---------------------------------------------------------------------------------------------------------------------

## VPC for isolation ##

# Creates an isolated virtual network for your resources, ensuring a secure and controlled
# environment. Isolation reduces the risk of unauthorized access to personal data.
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "gdpr_compliant"
  }
}

## Subnet for resources ##

# Provides a segregated subnet within the VPC, further isolating resources and controlling
# network access to protect personal data.
resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-west-1a"
  tags = {
    Name = "main_subnet"
  }
}
resource "aws_subnet" "main_subnet_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-west-1b"
  tags = {
    Name = "main_subnet_b"
  }
}

## RDS Subnet Group for PostgreSQL ##
resource "aws_db_subnet_group" "db_main" {
  name       = "db-main-subnet-group"
  subnet_ids = [aws_subnet.main_subnet.id, aws_subnet.main_subnet_b.id]

  tags = {
    Name = "db-main-subnet-group"
  }
}

## Internet Gateway ##

# Allows secure and controlled access to the internet for resources in the VPC, essential for
# securely transmitting data when necessary.
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "main_igw"
  }
}

## Route Table & Associate Subnet with Route Table ##

# Configures routing within the VPC to control traffic, ensuring that data flows securely
# within the network and to the internet only as required.
resource "aws_route_table" "main_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }
  tags = {
    Name = "main_rt"
  }
}
resource "aws_route_table_association" "main_rta" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_rt.id
}
resource "aws_route_table_association" "main_rta_b" {
  subnet_id      = aws_subnet.main_subnet_b.id
  route_table_id = aws_route_table.main_rt.id
}

# ---------------------------------------------------------------------------------------------------------------------
#### Encryption and Data Protection ####
# ---------------------------------------------------------------------------------------------------------------------

## KMS (key management service) Key for Encryption ##

# Manages encryption keys for data encryption, ensuring that all data at rest (in S3 buckets
# and RDS) is encrypted using a KMS key. Key rotation is enabled to enhance security, as
# recommended by GDPR.
resource "aws_kms_key" "mykey" {
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

# Stores data securely in S3 buckets, with logging and encryption configured to protect
# personal data and ensure auditability.
resource "aws_s3_bucket" "mybucket" {
  bucket = "my-unique-gdpr-compliant-bucket-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "gdpr_s3_bucket"
    Environment = "production"
  }
}
resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-unique-gdpr-log-bucket-12345"
  tags = {
    Name = "gdpr_log_bucket"
    Environment = "production"
  }
}

## S3 Bucket & S3 Bucket for Logs with Encryption ##

# Enforces encryption of data stored in S3 using KMS keys, ensuring that all data is 
# encrypted at rest as required by GDPR.
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_s3_mybucket" {
  bucket = aws_s3_bucket.mybucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_s3_log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Security Controls ####
# ---------------------------------------------------------------------------------------------------------------------

## Security Group for EC2 Instance and RDS ##

# Controls inbound and outbound traffic to your EC2 and RDS instances, restricting access 
# to only necessary services (e.g., HTTP, SSH) and protecting the data within these 
# instances from unauthorized access.
resource "aws_security_group" "web_sg" {
  name = "tf_web_sg"
  vpc_id = aws_vpc.main.id

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
    Name = "web_sg"
  }
}

## IAM Role for EC2 with Logging Permissions ##

# Manages permissions for EC2 instances, ensuring that only authorized services and roles 
# can access the S3 buckets. This enforces the principle of least privilege, which is crucial 
# for GDPR compliance.
resource "aws_iam_role" "example_ec2_role" {
  name = "example_ec2_role"

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
resource "aws_iam_role_policy" "example_s3_policy" {
  name = "example_s3_policy"
  role = aws_iam_role.example_ec2_role.id

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
          aws_s3_bucket.mybucket.arn,
          "${aws_s3_bucket.mybucket.arn}/*",
        ]
      },
    ]
  })
}
resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = aws_s3_bucket.log_bucket.id

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
        Resource = "${aws_s3_bucket.log_bucket.arn}/*",
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
        Resource = "${aws_s3_bucket.log_bucket.arn}"
      },

      # AWS Config permissions
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = [
          "s3:PutObject"       # Writing objects (requires /*)
        ],
        Resource = "${aws_s3_bucket.log_bucket.arn}/*",  # Apply to all objects in the bucket
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
        Resource = "${aws_s3_bucket.log_bucket.arn}"
      },
      # AWS Root User permissions
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "s3:GetBucketAcl",
        Resource = "${aws_s3_bucket.log_bucket.arn}"
      }
    ]
  })
}

## IAM Instance Profile for EC2 ##
resource "aws_iam_instance_profile" "example_ec2_profile" {
  name = "example_ec2_profile"
  role = aws_iam_role.example_ec2_role.name
}

# ---------------------------------------------------------------------------------------------------------------------
#### Compute Resources ####
# ---------------------------------------------------------------------------------------------------------------------

## EC2 Instance ##

# The EC2 instance is part of the GDPR-compliant infrastructure, configured within the VPC,
# and governed by the security group, IAM role, and instance profile. The instance is not
# publicly accessible, which protects any personal data processed on it.
resource "aws_instance" "web_server" {
  ami           = "ami-03cc8375791cb8bcf"  # Ubuntu AMI
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.main_subnet.id
  iam_instance_profile = aws_iam_instance_profile.example_ec2_profile.name
  monitoring = true

  # Attach security group
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    sudo apt-get update
    sudo apt-get install -y nginx
    echo "Hello, GDPR Compliant Server... Your are now Coldchain Secure!" > /var/www/html/index.html
    EOF

  tags = {
    Name = "web_server"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Database Configuration ####
# ---------------------------------------------------------------------------------------------------------------------

# The PostgreSQL RDS instance is securely deployed within the VPC subnet, with encryption e
# nabled for storage. It is also configured for high availability (Multi-AZ), ensuring that
# personal data is both secure and available as required by GDPR.

# RDS PostgreSQL Instance
resource "aws_db_instance" "postgres_instance" {
  identifier = "tf-postgres-instance"
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  db_name              = "mydb"
  username             = "postgres"
  password             = "postgres"
  parameter_group_name = "default.postgres15"
  db_subnet_group_name = aws_db_subnet_group.db_main.name
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  multi_az             = true
  publicly_accessible  = false
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.mykey.arn
  backup_retention_period = 7
  delete_automated_backups = true

  tags = {
    Name = "postgres_instance"
    Environment = "production"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
#### Monitoring and Logging ####
# ---------------------------------------------------------------------------------------------------------------------

## Enable CloudTrail for logging ##

# CloudTrail logs all API calls made in your AWS account, providing a comprehensive audit
# trail of activities. This helps in detecting, investigating, and responding to security
# incidents, fulfilling GDPR’s accountability and transparency requirements.
resource "aws_cloudtrail" "main" {
  name                          = "main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::${aws_s3_bucket.log_bucket.id}/*"
      ]
    }
  }
}

## AWS Config Delivery Channel ##

# Config continuously monitors your AWS resources, ensuring that they remain compliant with
# predefined configurations. This helps in maintaining an auditable record of the environment’s
# compliance status, which is crucial for GDPR.
resource "aws_config_delivery_channel" "main" {
  name           = "main"
  s3_bucket_name = aws_s3_bucket.log_bucket.bucket
  s3_key_prefix   = "aws-config-logs"
  s3_kms_key_arn = aws_kms_key.mykey.arn
}




# local Vars
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}
data "aws_caller_identity" "current" {}
