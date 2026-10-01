output "vpc_link_id" {
  description = "ID of the REST API VPC link."
  value       = aws_api_gateway_vpc_link.this.id
}

output "nlb_dns_name" {
  description = "DNS name of the NLB behind the VPC link."
  value       = aws_lb.this.dns_name
}
