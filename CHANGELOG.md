# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `reference/terraform/`: a Terraform stack that deploys REGIONAL REST and HTTP reference APIs
  (plus an echo Lambda, authorizers, Cognito, service targets, and a GitHub OIDC role) to measure
  parity against real API Gateway. See `reference/README.md`.

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
