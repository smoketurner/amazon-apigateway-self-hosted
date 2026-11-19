# Reference stack

Terraform that deploys real REGIONAL API Gateway APIs exercising every in-scope feature, so
`apigw` can be measured against what API Gateway actually does. The parity runner
(`crates/apigw-parity`) records responses from these APIs and replays the same requests
against `apigw`.

> [!WARNING]
> Use a dedicated test account or sandbox. Applying creates IAM roles, a Cognito user pool,
> Lambda functions with a public function URL (guarded by a shared secret), and two public
> API Gateway APIs. Nothing here is meant for production.

## Layout

```text
terraform/
  modules/                   reusable building blocks, one concern each
    lambda-backends/         echo Lambda, secret-guarded echo function URL, authorizer Lambda
    service-targets/         SQS, DynamoDB, Step Functions, EventBridge targets
    cognito/                 user pool, app client, test user
    integration-role/        role API Gateway assumes to call integrations and authorizers
    account-cloudwatch-role/ optional account-wide API Gateway CloudWatch role
    vpc-link/                optional internal NLB + VPC link
    ecs-gateway/             optional apigw itself on ECS Fargate, mirroring the reference REST API
    ecs-network/             optional public-subnet VPC for the ECS gateway
    rest-api/                reference REST API, stage, method settings, usage plan, API key
    rest-policy-api/         REST API with a resource policy
    http-api/                reference HTTP API and stage
    github-oidc/             GitHub OIDC provider and the read-only CI role
  environments/
    dev/                     the deployment of the reference APIs
```

Every module keeps data sources in `data.tf`, resources in `main.tf`, locals in `locals.tf`
(including `partition`, `account_id`, and `region` for building ARNs), and its interface in
`variables.tf` and `outputs.tf`. Modules declare minimum provider versions in `versions.tf`;
the environment pins exact versions and configures the provider and backend.

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

Gateway responses are customized only for `BAD_REQUEST_BODY`, `BAD_REQUEST_PARAMETERS`,
`THROTTLED`, and `DEFAULT_5XX`; the missing-token, unauthorized, and forbidden responses stay
stock so their default form can be recorded.

The echo Lambda accepts `echo_status=<code>`, `echo_binary=1`, and `echo_content_type=<mime>`
query parameters to control the response, and redacts the shared secret from the event it
returns. The authorizer returns Allow for the credential `allow`, Deny for `deny`, and raises
(401) for anything else; the credential is the `Authorization` token for the TOKEN
authorizer and the `x-auth` header for the REQUEST and HTTP API authorizers.

## Apply

State lives in S3. Copy `backend.hcl.example` to `backend.hcl` (gitignored) with your state
bucket, and optionally `terraform.tfvars.example` to `terraform.tfvars`:

```bash
cd terraform/environments/dev
cp backend.hcl.example backend.hcl        # set bucket, key, region
terraform init -backend-config=backend.hcl
terraform apply
terraform output -json parity_runner > ../../../parity/outputs.json
```

Variables worth knowing (all in `environments/dev/variables.tf`):

| Variable | Default | Effect |
|---|---|---|
| `region` | `us-east-1` | Region for everything |
| `name_prefix` | `apigw-ref` | Resource name prefix |
| `enable_logging` | `false` | Access logs and execution logs. REST APIs need the account-wide CloudWatch role |
| `manage_account_cloudwatch_role` | `false` | Creates the role and sets it in `aws_api_gateway_account`. This **overwrites** the account's current role, and destroying it clears the setting. Leave it off if the account already has one |
| `enable_cache_cluster` | `false` | Stage cache cluster (billed hourly while it exists) |
| `enable_vpc_link` | `false` | Internal NLB, VPC link, and a `/vpc-link` REST route. Needs `vpc_id` and `vpc_link_subnet_ids` |
| `enable_ecs_gateway` | `false` | `apigw` on ECS Fargate against the reference REST API. See [Running apigw on ECS](#running-apigw-on-ecs) |
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
| `ecs_gateway` | ECR repository, cluster, service, task role, and log group of the ECS gateway; `null` unless enabled |

## Running apigw on ECS

`enable_ecs_gateway` runs a build of `apigw` next to the real API it mirrors, so the two can
be compared request for request. It creates an ECR repository, a cluster and service with one
Fargate task, a security group, a log group, and two roles:

- the **task role** is the identity `apigw` makes AWS calls as. It may read the reference REST
  API's stage, export, usage plans, and API keys, invoke the echo and authorizer functions, and
  assume the integration role, whose trust policy gains the task role.
- the **execution role** only lets ECS pull the image and write logs.

`apigw` has no plaintext listener, so an init container generates a self-signed certificate
into a volume the gateway reads. The task gets a public IP; ports 8443 (API) and 9443 (admin)
are open only to `ecs_gateway_allowed_cidrs`, which may not include `0.0.0.0/0`.

```hcl
# terraform.tfvars
enable_ecs_gateway        = true
ecs_gateway_allowed_cidrs = ["203.0.113.7/32"] # curl -s https://checkip.amazonaws.com
ecs_gateway_image_tag     = "dev"
```

With no subnets given, the stack creates a small VPC with two public subnets and an internet
gateway for the task (`modules/ecs-network`). To use an existing network instead, set `vpc_id`
and `ecs_gateway_subnet_ids` to public subnets in it.

Apply, then build and push the image. The service retries until the image is there. Tags are
immutable, so a new build needs a new `ecs_gateway_image_tag` and another apply. The default
`cpu_architecture` is `ARM64`; build on an arm64 machine or pass `--platform linux/arm64`.

```bash
terraform apply
repo="$(terraform output -json ecs_gateway | jq -r .repository_url)"
aws ecr get-login-password | docker login --username AWS --password-stdin "${repo%%/*}"
docker build --platform linux/arm64 -t "$repo:dev" ../../..
docker push "$repo:dev"
```

Find the task's address and compare the gateway with API Gateway:

```bash
cluster="$(terraform output -json ecs_gateway | jq -r .cluster_name)"
task="$(aws ecs list-tasks --cluster "$cluster" --query 'taskArns[0]' --output text)"
eni="$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)"
ip="$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text)"

curl --insecure "https://$ip:9443/routes"                  # what apigw loaded, and role status
curl --insecure "https://$ip:8443/mock"                    # apigw
curl --insecure "https://$ip:8443/lambda-proxy"            # invokes the echo Lambda as the task role
curl "$(terraform output -json parity_runner | jq -r .rest.base_url)/mock"   # API Gateway
```

The gateway's logs are in the `log_group_name` from the `ecs_gateway` output. Set
`enable_ecs_gateway = false` and apply to remove it; the repository is deleted with its images.

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
cd terraform/environments/dev
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
- `enable_ecs_gateway`: one Fargate task (0.25 vCPU, 0.5 GB) while the service runs, and the
  image stored in ECR.

## Local checks

```bash
cd terraform
terraform fmt -check -recursive
(cd environments/dev && terraform init -backend=false && terraform validate)
python3 -m unittest discover -s modules/lambda-backends/functions
```

> [!IMPORTANT]
> The stack has been validated (`terraform validate`) and its OpenAPI templates rendered
> locally, but `terraform apply` has not been run against a real account yet. Expect to adjust
> an API Gateway import detail or two on the first deployment.
