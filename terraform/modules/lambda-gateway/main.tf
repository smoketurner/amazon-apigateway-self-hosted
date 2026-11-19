resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
}

# The function's role is the identity apigw's AWS credential chain resolves to.
resource "aws_iam_role" "this" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.this.name
  policy_arn = local.execution_policy_arn
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.this.id
  policy = var.gateway_policy_json
}

resource "aws_lambda_function" "this" {
  count = local.deploy_function ? 1 : 0

  function_name = local.name
  role          = aws_iam_role.this.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures = [var.cpu_architecture]
  memory_size   = local.memory_mb
  timeout       = local.timeout_seconds

  environment {
    variables = local.environment
  }

  depends_on = [
    aws_cloudwatch_log_group.this,
    aws_iam_role_policy.gateway,
    aws_iam_role_policy_attachment.logs,
  ]
}

# A function URL has no address filter: anyone who has the URL can call the
# gateway, exactly as they can call the public API it mirrors.
resource "aws_lambda_function_url" "this" {
  count = local.deploy_function ? 1 : 0

  function_name      = aws_lambda_function.this[0].function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "url" {
  count = local.deploy_function ? 1 : 0

  statement_id           = "AllowFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.this[0].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_invoke" {
  count = local.deploy_function ? 1 : 0

  statement_id             = "AllowFunctionUrlInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.this[0].function_name
  principal                = "*"
  invoked_via_function_url = true
}
