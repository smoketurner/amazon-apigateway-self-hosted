data "aws_partition" "current" {}

data "aws_region" "current" {}

data "archive_file" "echo" {
  type        = "zip"
  source_file = "${path.module}/functions/echo.py"
  output_path = "${path.module}/.build/echo.zip"
}

data "archive_file" "authorizer" {
  type        = "zip"
  source_file = "${path.module}/functions/authorizer.py"
  output_path = "${path.module}/.build/authorizer.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
