#!/bin/sh
# Creates the service account before the files it owns are unpacked.
set -e

if ! getent group apigw >/dev/null; then
  groupadd --system apigw
fi
if ! getent passwd apigw >/dev/null; then
  useradd --system --gid apigw --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --comment "apigw gateway" apigw
fi
