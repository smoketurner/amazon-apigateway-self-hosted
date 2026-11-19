#!/bin/sh
# Starts apigw on a loopback TLS listener and bridges the Lambda Web Adapter's
# plain HTTP to it. Only /tmp is writable in a Lambda sandbox.
set -eu

tls_dir=/tmp/apigw-tls
mkdir -p "$tls_dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -keyout "$tls_dir/tls.key" -out "$tls_dir/tls.crt" 2>/dev/null

export APIGW_LISTEN=127.0.0.1:8443
export APIGW_TLS_CERT="$tls_dir/tls.crt"
export APIGW_TLS_KEY="$tls_dir/tls.key"
export APIGW_CONFIG_CACHE=/tmp/apigw-config.json
# The bridge is the only peer apigw sees; the client address is in the
# X-Forwarded-For the function URL wrote.
export APIGW_TRUSTED_PROXIES=127.0.0.1/32

apigw &

exec nginx -e /dev/stderr -c /etc/apigw-bridge/nginx.conf
