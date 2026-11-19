#!/bin/sh
# $1 is the number of installs left: 0 on erase, 1 on upgrade.
set -e

if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
  systemctl --no-reload disable --now apigw.service
fi
