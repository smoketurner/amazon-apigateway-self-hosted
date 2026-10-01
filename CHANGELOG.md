# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Requests run through an explicit `Pipeline` in API Gateway's stage order, carrying a
  `RequestContext` that owns the `$context` variables used by events and, later, templates,
  gateway responses, and access logs.
- Lambda integrations invoke in the region from the function ARN (previously `AWS_REGION`),
  run as the integration's `credentials` role when it has one (`--integration-credentials`),
  propagate `X-Amzn-Trace-Id`, and can be pointed at a Runtime Interface Emulator with
  `--lambda-endpoint`. `/routes` reports the outcome of every role assumption.
- `--trusted-proxies` / `--trusted-proxy-hops` (`APIGW_TRUSTED_PROXIES`,
  `APIGW_TRUSTED_PROXY_HOPS`): the client address behind Istio or a load balancer is read from
  `X-Forwarded-For`, walking from the right, but only when the TCP peer is a trusted proxy.
  `sourceIp` in Lambda events reports it.
- `--proxy-protocol` (`APIGW_PROXY_PROTOCOL`): require a PROXY protocol v2 header on the API
  listener from trusted proxies, with a 5 second header timeout.
- Istio `X-Forwarded-Client-Cert` is parsed (Subject, Hash, URI/DNS SANs, `Cert`) from trusted
  proxies and kept with the client identity for upcoming mTLS support.

### Changed

- `X-Forwarded-For` sent by a client that is not a trusted proxy is no longer forwarded to
  `HTTP_PROXY` integrations: it is replaced by the client's address. `X-Forwarded-Client-Cert` is
  removed from such requests. Set `--trusted-proxies` to keep forwarding a proxy's headers.
- `terraform/`: Terraform modules and a `dev` environment that deploy REGIONAL REST and HTTP reference APIs
  (plus an echo Lambda, authorizers, Cognito, service targets, and a GitHub OIDC role) to measure
  parity against real API Gateway. See `terraform/README.md`.
- `ApiModel`: the export and `GetStage` are imported into one typed model covering
  integrations (all fields, `$ref` resolution), request parameters and bodies, validators,
  authorizers, models, gateway responses, binary media types, compression, API key source,
  CORS, resource policy, and stage settings (method/route settings, access logs, tracing,
  canary, caching). `/routes` lists every imported feature that is not enforced yet.
- Refresh calls `GetStage` first and re-downloads the export only when the deployment changed;
  failed refreshes back off exponentially with jitter.

### Fixed

- Resource policies and request validators were silently ignored because the REST export did
  not request them. The export now uses `extensions=apigateway,authorizers`; routes under a
  resource policy answer 403 and routes with a request validator answer 501 until those
  features are supported (`--unsupported-resource-policy` / `--unsupported-validation`
  `=ignore` to serve them). `--insecure-skip-authorization` does not skip resource policies.
- API key routes answer `403 Forbidden` and REST `AWS_IAM` routes `403 Missing Authentication
  Token`, matching API Gateway, instead of 401.
- REST APIs no longer apply a document-level `security` block to every method.
- HTTP API sources require `--stage`; without it the export was the latest, possibly
  undeployed, configuration.
