resource "aws_iam_openid_connect_provider" "github" {
  count = var.oidc_provider_arn == null ? 1 : 0

  url            = "https://${local.oidc_url}"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci" {
  name                 = "${var.name_prefix}-github-ci"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "read_reference_apis" {
  name   = "read-reference-apis"
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.read_reference_apis.json
}
