locals {
  name = "${var.name_prefix}-gateway"

  # One public subnet per zone, each a quarter of the VPC's block.
  subnet_cidrs = { for index, zone in var.availability_zones : zone => cidrsubnet(var.cidr_block, 2, index) }
}
