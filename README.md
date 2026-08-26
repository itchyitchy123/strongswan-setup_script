# strongSwan setup script

Interactive Bash installer for strongSwan IKEv2 connections using the traditional
`ipsec.conf` and `ipsec.secrets` starter workflow.

[![CI](https://github.com/itchyitchy123/strongswan-setup_script/actions/workflows/ci.yml/badge.svg)](https://github.com/itchyitchy123/strongswan-setup_script/actions/workflows/ci.yml)

## Supported Profiles

- Remote-access client using EAP-MSCHAPv2 username/password authentication.
- Remote-access client using a pre-shared key.
- Site-to-site tunnel using a pre-shared key.

## Supported Platforms

The installer supports systems with one of these package managers:

- Debian/Ubuntu: `apt-get`
- Fedora/RHEL family: `dnf` or `yum`

The runtime service is detected from `strongswan-starter.service`,
`strongswan.service`, `ipsec.service`, or the `ipsec` command.

## Safety Model

The script is designed to avoid leaving a host in a partially configured state:

- shows the generated connection block before writing it;
- creates timestamped backups of existing `/etc/ipsec.conf` and
  `/etc/ipsec.secrets`;
- installs `/etc/ipsec.secrets` with mode `0600`;
- validates configuration with `ipsec checkconfig` when available;
- restores the previous config if validation, restart, or connection loading
  fails;
- preserves or restores an existing CA certificate if the install overwrites one.

## Run

```sh
chmod +x install-strongswan.sh
sudo ./install-strongswan.sh
```

After setup:

```sh
sudo ipsec statusall
sudo ipsec up my-vpn
sudo ipsec down my-vpn
```

For username/password connections, provide the VPN server CA certificate when
prompted. The script only allows the CA prompt to be left blank when certificates
already exist in `/etc/ipsec.d/cacerts`. Do not disable server certificate
verification.

## Validate Locally

```sh
make check
```

Equivalent manual commands:

```sh
shellcheck install-strongswan.sh tests/run.sh
bash -n install-strongswan.sh tests/run.sh
bash tests/run.sh
```

## Production Notes

Before using this installer on a production host:

- Confirm identities, traffic selectors, and authentication method with the VPN
  administrator.
- Prefer certificate authentication or a long random PSK where possible.
- Restrict UDP ports 500 and 4500 according to the deployment firewall policy.
- On site-to-site gateways, configure forwarding, NAT, and routing separately.
  Those settings are network-specific and are deliberately not changed here.
- Confirm package and service names for the target distribution.
- Use a maintenance window when changing VPN configuration on a shared gateway.

## Scope

This project intentionally targets the legacy `ipsec.conf` starter workflow. It
does not manage a full `swanctl.conf` deployment, firewall policy, routing,
kernel forwarding settings, DNS, certificate issuance, or secrets rotation.
