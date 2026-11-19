#!/usr/bin/env bash
# Installs a built package in a clean container of its own distribution family
# and checks what it laid down, then removes it. The package must match the
# Docker host's architecture.
#
#   packaging/test-install.sh dist/apigw-2026.11.1-1.x86_64.rpm
#   packaging/test-install.sh dist/apigw_2026.11.1_amd64.deb
set -euo pipefail

package="$1"
dir="$(cd "$(dirname "$package")" && pwd)"
name="$(basename "$package")"

case "$name" in
*.rpm)
  image=almalinux:9
  # The signature is checked separately with rpmkeys; a dry-run RPM has none.
  install="dnf install -y --nogpgcheck systemd /pkg/$name"
  remove="dnf remove -y apigw"
  ;;
*.deb)
  image=debian:13
  install="apt-get update -qq && apt-get install -y -qq systemd /pkg/$name"
  remove="apt-get remove -y -qq apigw"
  ;;
*)
  echo "unsupported package: $name" >&2
  exit 1
  ;;
esac

docker run --rm --volume "$dir:/pkg:ro" --env DEBIAN_FRONTEND=noninteractive "$image" sh -euc "
  $install
  apigw --version
  getent passwd apigw
  test \"\$(stat -c '%a %U:%G' /etc/apigw/apigw.env)\" = '640 root:apigw'
  test \"\$(stat -c '%a %U:%G' /etc/apigw/tls)\" = '750 root:apigw'
  test -f /usr/share/doc/apigw/LICENSE-APACHE
  systemd-analyze verify /usr/lib/systemd/system/apigw.service
  $remove
  test ! -e /usr/bin/apigw
"
