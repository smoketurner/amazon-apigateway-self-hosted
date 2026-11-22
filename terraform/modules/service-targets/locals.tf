locals {
  account_id = data.aws_caller_identity.current.account_id

  event_source = "apigw.reference"

  # Bucket names are global, so the account keeps them apart.
  bucket_name = "${var.name_prefix}-target-${local.account_id}"

  state_machine_definition = {
    Comment = "Returns its input so the parity runner can see what API Gateway sent."
    StartAt = "Echo"
    States = {
      Echo = {
        Type = "Pass"
        End  = true
      }
    }
  }
}
