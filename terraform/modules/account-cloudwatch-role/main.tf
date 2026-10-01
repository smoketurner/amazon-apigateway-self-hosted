resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-apigateway-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "this" {
  role       = aws_iam_role.this.name
  policy_arn = local.push_to_logs_policy_arn
}

# Account-wide singleton: applying overwrites the account's current setting and
# destroying clears it.
resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.this.arn

  depends_on = [aws_iam_role_policy_attachment.this]
}
