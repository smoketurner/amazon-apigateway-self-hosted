locals {
  event_source = "apigw.reference"

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
