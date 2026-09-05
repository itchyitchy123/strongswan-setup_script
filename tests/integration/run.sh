#!/bin/sh
set -eu

strongswan-setup \
  --non-interactive --yes \
  --profile psk-client --name integration-office \
  --gateway 198.51.100.10 --remote-id vpn.example.test \
  --remote-ts 10.20.0.0/24 --psk integration-test-secret

ipsec checkconfig
ipsec statusall | grep -F 'integration-office'

strongswan-setup --remove --yes --name integration-office
if ipsec statusall | grep -Fq 'integration-office'; then
  echo 'managed connection remained after removal' >&2
  exit 1
fi
