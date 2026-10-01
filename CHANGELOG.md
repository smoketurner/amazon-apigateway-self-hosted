# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
