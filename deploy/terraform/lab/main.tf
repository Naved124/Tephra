# SPDX-License-Identifier: Apache-2.0
#
# One lab instance for Tephra: the same Ubuntu and toolchain as the laptop VM
# (deploy/vm), on EC2. It runs the kind lab cluster, the attack harness and
# the benchmarks.
#
# Nothing listens on the internet. The security group has no inbound rule;
# the instance is reached through AWS Systems Manager, which the instance
# dials out to, and SSH runs inside that session.

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  default_tags {
    tags = {
      project = "tephra-demo"
      lab     = var.name
    }
  }
}

variable "name" {
  description = "Name of the instance; one Terraform workspace per name."
  type        = string
  default     = "tephra-dev"
}

variable "instance_type" {
  type    = string
  default = "m7i.xlarge"
}

variable "ubuntu_version" {
  description = "Ubuntu LTS release of the image."
  type        = string
  default     = "24.04"
}

variable "disk_gib" {
  type    = number
  default = 60
}

variable "user_data" {
  description = "Rendered cloud-init (deploy/vm/user-data.yaml.tmpl with the lab's public key)."
  type        = string
}

data "aws_ssm_parameter" "ami" {
  name = "/aws/service/canonical/ubuntu/server/${var.ubuntu_version}/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_availability_zones" "up" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.77.1.0/24"
  availability_zone       = data.aws_availability_zones.up.names[0]
  map_public_ip_on_launch = true # outbound only: the security group admits nothing
  tags                    = { Name = var.name }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = var.name }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

resource "aws_security_group" "lab" {
  name        = var.name
  description = "Tephra lab instance: no inbound, all outbound"
  vpc_id      = aws_vpc.lab.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = var.name }
}

resource "aws_iam_role" "lab" {
  name = "${var.name}-ssm"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.lab.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "lab" {
  name = "${var.name}-ssm"
  role = aws_iam_role.lab.name
}

resource "aws_instance" "lab" {
  ami                    = nonsensitive(data.aws_ssm_parameter.ami.value)
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.lab.id]
  iam_instance_profile   = aws_iam_instance_profile.lab.name
  user_data              = var.user_data

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1 # containers on the instance cannot reach its credentials
  }

  root_block_device {
    volume_size = var.disk_gib
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = var.name }

  lifecycle {
    # A newer image or an edited cloud-init must not replace a lab that
    # holds a run in progress.
    ignore_changes = [ami, user_data]
  }
}

output "instance_id" {
  value = aws_instance.lab.id
}
