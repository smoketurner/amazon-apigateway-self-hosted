data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

resource "random_password" "echo_shared_secret" {
  length  = 40
  special = false
}

data "archive_file" "echo" {
  type        = "zip"
  source_file = "${path.module}/lambda/echo.py"
  output_path = "${path.module}/.build/echo.zip"
}

data "archive_file" "authorizer" {
  type        = "zip"
  source_file = "${path.module}/lambda/authorizer.py"
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

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.name_prefix}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "echo" {
  name              = "/aws/lambda/${var.name_prefix}-echo"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "echo_url" {
  name              = "/aws/lambda/${var.name_prefix}-echo-url"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "authorizer" {
  name              = "/aws/lambda/${var.name_prefix}-authorizer"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "echo" {
  function_name    = "${var.name_prefix}-echo"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = var.function_runtime
  handler          = "echo.handler"
  filename         = data.archive_file.echo.output_path
  source_code_hash = data.archive_file.echo.output_base64sha256
  timeout          = 10
  memory_size      = 128

  logging_config {
    log_group  = aws_cloudwatch_log_group.echo.name
    log_format = "Text"
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_logs]
}

resource "aws_lambda_function" "echo_url" {
  function_name    = "${var.name_prefix}-echo-url"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = var.function_runtime
  handler          = "echo.handler"
  filename         = data.archive_file.echo.output_path
  source_code_hash = data.archive_file.echo.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      ECHO_SHARED_SECRET = random_password.echo_shared_secret.result
    }
  }

  logging_config {
    log_group  = aws_cloudwatch_log_group.echo_url.name
    log_format = "Text"
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_logs]
}

resource "aws_lambda_function_url" "echo" {
  function_name      = aws_lambda_function.echo_url.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "echo_url_invoke_url" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.echo_url.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "echo_url_invoke_function" {
  statement_id             = "FunctionURLInvokeAllowPublicAccess"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.echo_url.function_name
  principal                = "*"
  invoked_via_function_url = true
}

resource "aws_lambda_function" "authorizer" {
  function_name    = "${var.name_prefix}-authorizer"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = var.function_runtime
  handler          = "authorizer.handler"
  filename         = data.archive_file.authorizer.output_path
  source_code_hash = data.archive_file.authorizer.output_base64sha256
  timeout          = 5
  memory_size      = 128

  logging_config {
    log_group  = aws_cloudwatch_log_group.authorizer.name
    log_format = "Text"
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_logs]
}

locals {
  echo_function_host = trimsuffix(trimprefix(aws_lambda_function_url.echo.function_url, "https://"), "/")

  echo_invocation_uri       = "arn:${local.partition}:apigateway:${var.region}:lambda:path/2015-03-31/functions/${aws_lambda_function.echo.arn}/invocations"
  authorizer_invocation_uri = "arn:${local.partition}:apigateway:${var.region}:lambda:path/2015-03-31/functions/${aws_lambda_function.authorizer.arn}/invocations"

  stage_variables = {
    echo_host = local.echo_function_host
  }
}
