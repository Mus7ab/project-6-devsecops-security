# Controlled vulnerable example
# Source: Project 1 (three-tier-webapp) - terraform/security_groups.tf
# Known issue: RDS security group allows unrestricted egress (0.0.0.0/0, all ports/protocols)

resource "aws_security_group" "rds" {
  name        = "example-rds-sg"
  description = "Allow PostgreSQL from EC2 instances"
  vpc_id      = "vpc-EXAMPLE"

  ingress {
    description     = "PostgreSQL from EC2"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = ["sg-EXAMPLE"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "example-rds-sg"
  }
}
