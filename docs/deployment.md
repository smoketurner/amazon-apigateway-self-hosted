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

Behind a proxy, the TCP peer is the proxy. `apigw` appends the peer address to
`X-Forwarded-For` on `HTTP_PROXY` requests and reports it as `sourceIp` in Lambda events; it
does not yet trust an incoming `X-Forwarded-For` or the PROXY protocol, so Lambda functions
see the proxy's address, not the client's.

## Authorization

`apigw` does not evaluate Lambda authorizers, JWT/Cognito authorizers, IAM auth, or API keys.
Routes that require them answer `401` by default and are flagged on `/routes`. If
authentication happens in front of `apigw` (an Istio `RequestAuthentication` +
`AuthorizationPolicy`, an OAuth proxy), set `--insecure-skip-authorization` to serve them.
