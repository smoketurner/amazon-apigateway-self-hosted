locals {
  name = "${var.name_prefix}-rest-policy"

  policy_document = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*"
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*/GET/ip-denied"
        Condition = {
          IpAddress = { "aws:SourceIp" = ["0.0.0.0/0", "::/0"] }
        }
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*/GET/ip-restricted"
        Condition = {
          NotIpAddress = { "aws:SourceIp" = var.restricted_cidrs }
        }
      },
    ]
  }

  openapi = yamldecode(templatefile("${path.module}/templates/openapi.yaml.tftpl", {
    name        = local.name
    policy_json = jsonencode(local.policy_document)
  }))
}
