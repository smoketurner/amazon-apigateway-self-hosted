resource "aws_iam_role" "this" {
  name               = local.role_name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "targets" {
  name   = "targets"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.invoke.json
}
