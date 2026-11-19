# syntax=docker/dockerfile:1
#
# apigw as a Lambda function behind a function URL, for testing only.
#
# apigw is a server with TLS-only listeners; Lambda hands a function events.
# The Lambda Web Adapter turns events into HTTP requests but cannot speak TLS
# to the application, so nginx bridges the adapter's plain HTTP on loopback to
# apigw's TLS listener. apigw itself is unchanged and still serves only TLS.
#
#   docker build --platform linux/arm64 \
#     --build-arg APIGW_IMAGE=<an apigw image> -t <repository>:<tag> \
#     terraform/modules/lambda-gateway/image

ARG APIGW_IMAGE=apigw:local

FROM ${APIGW_IMAGE} AS apigw

FROM public.ecr.aws/awsguru/aws-lambda-adapter:1.1.0 AS adapter

FROM public.ecr.aws/docker/library/alpine:3.24
RUN apk add --no-cache openssl nginx nginx-mod-http-headers-more
COPY --from=adapter /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=apigw /apigw /usr/local/bin/apigw
COPY nginx.conf /etc/apigw-bridge/nginx.conf
COPY --chmod=0755 start.sh /usr/local/bin/start.sh

# The adapter waits for a response on this port before the function is ready;
# any status below 500 counts, and an unknown path answers 403 or 404.
ENV AWS_LWA_PORT=8080

ENTRYPOINT ["/usr/local/bin/start.sh"]
