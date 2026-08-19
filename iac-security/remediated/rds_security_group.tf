# Remediated version
# Source: Project 1 (three-tier-webapp) - terraform/security_groups.tf
# Fix: Removed unrestricted egress rule (0.0.0.0/0, all ports/protocols).
# Terraform manages security group rules declaratively - omitting the
# egress block results in zero egress rules (deny-all), unlike a
# console-created SG which defaults to allow-all-egress.
# No outbound dependency identified for this RDS instance as of this scan.

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

  tags = {
    Name = "example-rds-sg"
  }
}
