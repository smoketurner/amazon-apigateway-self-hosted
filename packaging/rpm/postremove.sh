#!/bin/sh
# $1 is the number of installs left: 0 on erase, 1 on upgrade.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if [ "$1" -ge 1 ]; then
    systemctl try-restart apigw.service
  fi
fi
