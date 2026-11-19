#!/bin/sh
# The service is not enabled or started on a first install: it cannot run until
# /etc/apigw/apigw.env names an API and a certificate. $2 is the version being
# upgraded from, empty on a first install.
set -e

if [ "$1" = "configure" ] && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if [ -n "$2" ]; then
    systemctl try-restart apigw.service
  fi
fi
