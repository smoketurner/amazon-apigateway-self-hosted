# Deployment

`apigw` ships as a static musl binary in a distroless, non-root image (`Dockerfile`). It is
built for Kubernetes on any cloud or on-prem, optionally behind Istio.

```bash
docker build -t apigw:local .   # or: make image
```

The image sets `APIGW_LISTEN=0.0.0.0:8443`, `APIGW_ADMIN_LISTEN=0.0.0.0:9443`, and
`APIGW_CONFIG_CACHE=/var/cache/apigw/config.json`.

## TLS

Every listener terminates TLS (rustls with aws-lc-rs); there is no plaintext port and no
80→443 redirect, matching API Gateway's HTTPS-only `execute-api` endpoints. Certificates are
PEM files, polled every 30 seconds and swapped in without a restart. A file that fails to
parse, or a key that doesn't match the certificate, is logged and the previous certificate
keeps serving. This works with cert-manager-managed Secrets, which Kubernetes updates through
an atomic symlink swap.

Connection handling follows the vouch-server accept loop: hyper is driven directly so its
timers work, giving a 5 s TLS handshake limit, a 10 s request-header limit, an idle limit
that also covers HTTP/2, a per-listener connection cap (`--max-connections`), and a 30 s
drain on SIGTERM.

## AWS credentials outside AWS

There is no IRSA or EKS Pod Identity off AWS. Options, in order of preference:

1. **IAM Roles Anywhere** — short-lived credentials from an X.509 certificate through
   `credential_process`. The distroless image has no `aws_signing_helper`, so build a derived
   image that adds it and mount an AWS config file:

   ```ini
   [default]
   credential_process = /aws_signing_helper credential-process --certificate /etc/rolesanywhere/tls.crt --private-key /etc/rolesanywhere/tls.key --trust-anchor-arn ... --profile-arn ... --role-arn ...
   ```

2. **Web identity federation** — if the cluster's service-account issuer is registered as an
   IAM OIDC provider, set `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` to a projected
   service-account token.
3. **Static access keys** from a Secret (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) —
   simplest, but long-lived; scope the IAM user to the permissions in the README.

Always set `AWS_REGION` to the API's region.

## Integration roles

In AWS, API Gateway invokes integrations as the integration's `credentials` role, and Lambda
functions allow `apigateway.amazonaws.com` in their resource policies. Outside AWS the gateway's
own principal does the calling, so:

- **Integration roles** (`credentials` on an integration): add the gateway's principal to the
  role's trust policy alongside API Gateway, and grant the gateway `sts:AssumeRole` on it.

  ```json
  {
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/apigw-self-hosted" },
    "Action": "sts:AssumeRole"
  }
  ```

  `/routes` reports each role the gateway tried to assume and whether it worked. With
  `--integration-credentials=gateway` the roles are ignored and the gateway's own credentials
  are used.
- **Lambda authorizers** are invoked like Lambda integrations: with the `authorizerCredentials`
  role when the authorizer has one (same trust policy requirement as above), otherwise as the
  gateway's principal. An authorizer that cannot be invoked or answers in an invalid format
  answers `500`, as API Gateway does; check the gateway's logs.
- **Lambda functions without a role**: grant the gateway's principal `lambda:InvokeFunction`
  (identity policy, or the function's resource policy for cross-account functions).
- **Caller passthrough** (`arn:aws:iam::*:user/*`) needs IAM-authenticated callers and cannot
  work outside AWS; those routes answer 501.

Lambda clients use the region in each function's ARN, so functions in several regions work
from one gateway.

## Running Lambda functions in-cluster

`--lambda-endpoint FUNCTION=URL` (repeatable, or comma-separated in `APIGW_LAMBDA_ENDPOINTS`)
sends a function's invocations to a URL that speaks Lambda's Invoke protocol instead of to AWS.
The AWS Lambda base images include the Runtime Interface Emulator, so a function's container
image can run as a Deployment unchanged:

```bash
--lambda-endpoint pets=http://pets.default.svc:8080/2015-03-31/functions/function/invocations
```

`FUNCTION` is the function name or full ARN from the integration. The emulator's response body
is the function's payload; an `X-Amz-Function-Error` header marks a function error, as with Lambda.
The SDK also honors `AWS_ENDPOINT_URL_LAMBDA` (and `AWS_ENDPOINT_URL`) for LocalStack-style
emulators that implement the full Lambda API.

## VPC links

A VPC link's load balancer or Cloud Map service is private to the VPC and cannot be reached
from outside AWS, so routes with `connectionType: VPC_LINK` answer `501` (the reason is on
`/routes`) until their connection ID is mapped to an in-cluster URL that serves the same
backend:

```bash
--vpc-link abc123=http://pets.default.svc:8080
```

`--vpc-link CONNECTION_ID=URL` is repeatable, or comma-separated in `APIGW_VPC_LINKS`. The ID
is the integration's `connectionId`; a `${stageVariables.name}` connection ID is resolved first.
How the URL is used follows API Gateway:

- **REST APIs** (NLB): the integration URI's host is only the `Host` header on API Gateway, and
  traffic goes to the load balancer. Here the request goes to the mapped URL, keeping the
  URI's path and query, and the URI's host (and port) is sent as the `Host` header.
- **HTTP APIs** (ALB, NLB, or Cloud Map): the integration URI is a listener or service ARN.
  The request path is sent to the mapped URL, preceded by the stage name unless the stage is
  `$default`, as API Gateway does; `overwrite:path` parameter mapping can change that.

An `https` URL is verified against its own host name. Only `HTTP_PROXY` integrations can use a
VPC link. NLB/ALB DNS names and Cloud Map instances are not resolved automatically: those names
and the addresses `DiscoverInstances` returns are private to the VPC, so resolving them from
another network fails or reaches the wrong place; the explicit mapping cannot.

## Kubernetes

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: apigw-tls }
spec:
  secretName: apigw-tls
  dnsNames: [apigw.default.svc, api.example.com]
  issuerRef: { name: internal-ca, kind: ClusterIssuer }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: apigw }
spec:
  replicas: 2
  selector: { matchLabels: { app: apigw } }
  template:
    metadata: { labels: { app: apigw } }
    spec:
      terminationGracePeriodSeconds: 45   # above the 30 s connection drain
      containers:
        - name: apigw
          image: ghcr.io/smoketurner/amazon-apigateway-self-hosted:latest
          env:
            - { name: APIGW_REST_API_ID, value: a1b2c3d4e5 }
            - { name: APIGW_STAGE, value: prod }
            - { name: AWS_REGION, value: us-east-1 }
            - { name: APIGW_TLS_CERT, value: /etc/apigw/tls/tls.crt }
            - { name: APIGW_TLS_KEY, value: /etc/apigw/tls/tls.key }
            - { name: APIGW_STAGE_VARIABLE_petsHost, value: "pets.default.svc:8080" }
          ports:
            - { name: https, containerPort: 8443 }
            - { name: admin, containerPort: 9443 }
          readinessProbe:
            httpGet: { path: /healthz, port: admin, scheme: HTTPS }
          livenessProbe:
            httpGet: { path: /healthz, port: admin, scheme: HTTPS }
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ALL] }
          volumeMounts:
            - { name: tls, mountPath: /etc/apigw/tls, readOnly: true }
            - { name: cache, mountPath: /var/cache/apigw }
      volumes:
        - { name: tls, secret: { secretName: apigw-tls } }
        - { name: cache, emptyDir: {} }
---
apiVersion: v1
kind: Service
metadata: { name: apigw }
spec:
  selector: { app: apigw }
  ports: [{ name: https, port: 443, targetPort: https, appProtocol: https }]
```

The pod is ready once the first definition has loaded: `apigw` binds its listeners only
after a successful download (or a cache hit), and exits non-zero if neither is available.
Keep the admin port off any Ingress — `/routes` lists every backend target.

An `emptyDir` cache survives container restarts but not pod rescheduling. Use a
`PersistentVolumeClaim` if pods must start while AWS is unreachable after being rescheduled.

## Istio

Because `apigw` always serves TLS, tell the mesh how to reach it. Either:

- **Terminate at the ingress gateway and re-encrypt to the pod** (the gateway sees HTTP, so
  routing, retries, and authorization policies work):

  ```yaml
  apiVersion: networking.istio.io/v1
  kind: DestinationRule
  metadata: { name: apigw }
  spec:
    host: apigw.default.svc.cluster.local
    trafficPolicy:
      tls: { mode: SIMPLE, sni: apigw.default.svc }
  ```

- **Pass TLS through** with a `Gateway` server in `tls.mode: PASSTHROUGH` and a
  `VirtualService` `tls` route, so the certificate clients see is the one `apigw` serves.

With a sidecar injected, `appProtocol: https` on the Service port tells Istio the traffic is
already TLS, so the sidecar forwards it (inside its own mTLS) without trying to parse HTTP.

### Client IP

`sourceIp` in Lambda events, and later `aws:SourceIp` in resource policies and per-IP
throttling, need the client's address, but behind Istio or a load balancer the TCP peer is the
proxy. Forwarding headers are written by whoever sends the request, so `apigw` believes them
only from proxies you name:

| Setting | Behavior |
|---|---|
| `--trusted-proxies` unset | The TCP peer is the client. An incoming `X-Forwarded-For` is replaced by the peer address and `X-Forwarded-Client-Cert` is removed before the request reaches an integration. |
| Peer inside `--trusted-proxies` | The client is read from `X-Forwarded-For`, walking from the right: with `--trusted-proxy-hops 1` (default) the last entry, with 2 the one before it, and so on. The walk stops early at the first address outside `--trusted-proxies`. Entries to the left of the client are never read, so a client cannot spoof its address by sending its own header. The peer is appended to `X-Forwarded-For` for the integration, and `X-Forwarded-Client-Cert` is kept and parsed. |
| Peer outside `--trusted-proxies` | The TCP peer is the client; any `X-Forwarded-For` it sent is ignored. |

A trusted peer that sends no `X-Forwarded-For` is the client itself. If it sends one that cannot be
read (an entry that is not an address, an empty entry, fewer entries than `--trusted-proxy-hops`
when every one is a trusted proxy), the client address is **unknown**: Lambda events carry no
`sourceIp`, and features that depend on the address must refuse the request instead of guessing.

For Istio, `--trusted-proxies` must cover the address the sidecar (or the ingress gateway, when
`apigw` runs behind one) connects from, which is a loopback or pod address, not the client's.
`--trusted-proxy-hops` follows Envoy's `xff_num_trusted_hops`, which Istio exposes as
`gatewayTopology.numTrustedProxies`: use the same number the mesh is configured with. How many
entries the mesh appends depends on that configuration, so check a request's `X-Forwarded-For`
at the application once before relying on the setting.

**PROXY protocol.** A load balancer or Istio `PASSTHROUGH` gateway that relays TLS without
terminating it cannot add headers. Start `apigw` with `--proxy-protocol` (requires
`--trusted-proxies`) and have the proxy send a PROXY protocol **v2** header: its source address
becomes the client. The header is mandatory on `--listen` (the admin listener never takes one),
connections from peers outside `--trusted-proxies` are closed without being read, v1 and datagram
headers are refused, a header that does not arrive within 5 seconds closes the connection, and a
`LOCAL` header (a proxy's own health check) keeps the TCP peer as the client. After the header, the
connection is treated like any other whose peer is the header's source: its `X-Forwarded-For` is
believed only if that source is itself a trusted proxy.

**Client certificates.** Istio's `X-Forwarded-Client-Cert` (Subject, Hash, URI and DNS SANs, and
the PEM `Cert`) is parsed only from trusted peers and recorded with the request's client
identity; nothing authenticates with it yet. A header that cannot be parsed is recorded as
malformed.

## Authorization

`apigw` fails closed on every access control it does not evaluate yet, answering the way API
Gateway answers a caller who fails that check, and lists each one per route on `/routes`:

| Protection | Default response | To serve the route anyway |
|---|---|---|
| Resource policy (any statement) | `403 Forbidden` | `--unsupported-resource-policy=ignore` |
| IAM (`AWS_IAM`) | REST `403 Missing Authentication Token`, HTTP `403 Forbidden` | `--insecure-skip-authorization` |
| Cognito or JWT authorizer, or a Lambda authorizer that cannot be evaluated (see `/routes`) | `401 Unauthorized` | `--insecure-skip-authorization` |
| API key | `403 Forbidden` | `--insecure-skip-authorization` |
| Request validator | `501` | `--unsupported-validation=ignore` |

Checks run in API Gateway's order, so a request gets the first applicable response. If
authentication happens in front of `apigw` (an Istio `RequestAuthentication` +
`AuthorizationPolicy`, an OAuth proxy), `--insecure-skip-authorization` serves authenticated
routes. It deliberately does not cover resource policies: an IP allowlist is not something a
front proxy usually enforces, so ignoring one is a separate, explicit choice.
