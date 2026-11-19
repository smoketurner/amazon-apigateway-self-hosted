#!/bin/sh
set -e

if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
  systemctl --no-reload disable --now apigw.service
fi
