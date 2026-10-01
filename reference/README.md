# Reference stack

Terraform that deploys real REGIONAL API Gateway APIs exercising every in-scope feature, so
`apigw` can be measured against what API Gateway actually does. The parity runner
(`crates/apigw-parity`) records responses from these APIs and replays the same requests
against `apigw`.

> [!WARNING]
> Use a dedicated test account or sandbox. Applying creates IAM roles, a Cognito user pool,
> Lambda functions with a public function URL (guarded by a shared secret), and two public
> API Gateway APIs. Nothing here is meant for production.

## What it deploys

| Area | Resources |
|---|---|
| REST API (`<prefix>-rest`) | `HTTP_PROXY`, `AWS_PROXY` (payload 1.0), `MOCK` (plain, non-200, VTL-rendered), `HTTP` and `AWS` non-proxy integrations with mapping templates, request validators and a body model, gateway responses, binary media types, API key + usage plan, TOKEN and REQUEST Lambda authorizers, a Cognito authorizer (with and without scopes), CORS, stage variables, method settings and throttling, optional access logs, optional cache cluster, optional VPC-link route |
| REST API with a resource policy (`<prefix>-rest-policy`) | Separate API so the policy cannot block the others. `/open` is allowed, `/ip-restricted` is denied outside `policy_restricted_cidrs`, `/ip-denied` is always denied |
| HTTP API (`<prefix>-http`) | `HTTP_PROXY`, `AWS_PROXY` 1.0 and 2.0, the `$default` route, parameter mapping (path, query, header, response), CORS, JWT authorizer (with and without scopes), Lambda authorizers (simple response and IAM policy), route throttling, optional access logs |
| Backends | Python echo Lambda (returns the event it received); the same echo behind a Lambda function URL that requires a shared-secret `x-echo-secret` header, used as the HTTP backend through the `echo_host` and `echo_secret` stage variables; a deterministic authorizer Lambda |
| Identity | Cognito user pool, app client (`USER_PASSWORD_AUTH`), and a test user |
| Service targets | SQS queue, DynamoDB table, Step Functions EXPRESS state machine, EventBridge bus (events are also written to a log group) |
| CI | GitHub OIDC provider (unless you pass an existing one) and a read-only role for the nightly workflow |

The echo Lambda accepts `echo_status=<code>`, `echo_binary=1`, and `echo_content_type=<mime>`
query parameters to control the response, and redacts the shared secret from the event it
returns. The authorizer returns Allow for the credential `allow`, Deny for `deny`, and raises
(401) for anything else; the credential is the `Authorization` token for the TOKEN
authorizer and the `x-auth` header for the REQUEST and HTTP API authorizers.

## Apply

```bash
cd reference/terraform
terraform init
terraform apply
terraform output -json parity_runner > ../../parity/outputs.json
```

Variables worth knowing (all in `variables.tf`):

| Variable | Default | Effect |
|---|---|---|
| `region` | `us-east-1` | Region for everything |
| `name_prefix` | `apigw-ref` | Resource name prefix |
| `enable_logging` | `false` | Access logs and execution logs. REST APIs need the account-wide CloudWatch role |
| `manage_account_cloudwatch_role` | `false` | Creates the role and sets it in `aws_api_gateway_account`. This **overwrites** the account's current role, and destroying it clears the setting. Leave it off if the account already has one |
| `enable_cache_cluster` | `false` | Stage cache cluster (billed hourly while it exists) |
| `enable_vpc_link` | `false` | Internal NLB, VPC link, and a `/vpc-link` REST route. Needs `vpc_id` and `vpc_link_subnet_ids` |
| `github_repository` | this repository | Repository allowed to assume the CI role |
| `github_oidc_provider_arn` | `null` | Reuse an existing GitHub OIDC provider instead of creating one |

> [!NOTE]
> A clean account has no API Gateway CloudWatch role, so `enable_logging = true` fails on the
> first apply unless you also set `manage_account_cloudwatch_role = true`.

## Outputs

| Output | Use |
|---|---|
| `parity_runner` | JSON with API IDs, base URLs, stage, stage variables, and Cognito identifiers. Input to `apigw-parity record` |
| `api_key_value` (sensitive) | Value of the usage-plan key for `/keyed` |
| `cognito_test_password` (sensitive) | Password of the Cognito test user |
| `echo_shared_secret` (sensitive) | Secret the echo function URL requires |
| `github_ci_role_arn` | Role for the nightly workflow |

## Nightly parity workflow

`.github/workflows/parity.yml` assumes the CI role with GitHub OIDC. Configure the repository
with:

| Kind | Name | Value |
|---|---|---|
| Variable | `PARITY_AWS_ROLE_ARN` | `github_ci_role_arn` |
| Variable | `PARITY_AWS_REGION` | the stack's region |
| Variable | `PARITY_OUTPUTS` | the `parity_runner` JSON |
| Secret | `PARITY_API_KEY` | `api_key_value` |
| Secret | `PARITY_COGNITO_PASSWORD` | `cognito_test_password` |

The role can only read the reference APIs' stage and export (`apigateway:GET` on
`/restapis/<id>/stages/<stage>`, `.../exports/*`, `/apis/<id>/exports/*`, and
`/apis/<id>/stages/<stage>`). It cannot invoke or modify anything.

## Destroy

```bash
cd reference/terraform
terraform destroy
```

Destroy removes everything the stack created, including the log groups. If
`manage_account_cloudwatch_role` was set, it also clears the account's API Gateway CloudWatch
role.

## Cost

With the defaults the stack is within the free tier or costs cents per month when idle:
Lambda, API Gateway, SQS, DynamoDB (on demand), Step Functions, EventBridge, Cognito, and
CloudWatch Logs bill per request or per GB. Two opt-in switches bill by the hour while they
exist, so apply them only for a test and destroy afterwards:

- `enable_cache_cluster`: a 0.5 GB REST API cache cluster.
- `enable_vpc_link`: an internal Network Load Balancer.

## Local checks

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
python3 -m unittest discover -s lambda
```

> [!IMPORTANT]
> The stack has been validated (`terraform validate`) and its OpenAPI templates rendered
> locally, but `terraform apply` has not been run against a real account yet. Expect to adjust
> an API Gateway import detail or two on the first deployment.
