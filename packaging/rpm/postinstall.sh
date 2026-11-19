#!/bin/sh
# The service is not enabled or started: it cannot run until
# /etc/apigw/apigw.env names an API and a certificate.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
