# strongSwan interactive installer

`install-strongswan.sh` installs strongSwan and walks through configuring one
IKEv2 connection. It supports:

- a remote-access client using EAP-MSCHAPv2 (username and password);
- a remote-access client using a pre-shared key; and
- a site-to-site tunnel using a pre-shared key.

The installer supports Debian/Ubuntu (`apt-get`) and Fedora/RHEL-family systems
(`dnf` or `yum`). It writes the traditional `ipsec.conf` configuration used by
the strongSwan starter service.

## Run it

```sh
chmod +x install-strongswan.sh
sudo ./install-strongswan.sh
```

The script shows the generated connection before writing it. Existing config
files are backed up with a timestamp, `/etc/ipsec.secrets` is installed with
mode `0600`, and the previous config is restored if validation, restart, or
connection loading fails.

After setup:

```sh
sudo ipsec statusall
sudo ipsec up my-vpn
sudo ipsec down my-vpn
```

For username/password connections, provide the VPN server's CA certificate when
prompted. The script only allows this prompt to be left blank when certificates
already exist in `/etc/ipsec.d/cacerts`; do not disable server certificate
verification.

## Test it

```sh
shellcheck install-strongswan.sh tests/run.sh
bash -n install-strongswan.sh tests/run.sh
bash tests/run.sh
```

## Before using it in production

- Confirm the identities, traffic selectors, and authentication method with the
  VPN administrator.
- Prefer certificate authentication or a long random PSK where possible.
- Restrict UDP ports 500 and 4500 according to the deployment's firewall policy.
- On a site-to-site gateway, enable IP forwarding and configure forwarding and
  NAT rules separately; those settings are network-specific and are deliberately
  not changed by this installer.
- Confirm package and service names for the target distribution. This installer
  targets the traditional `ipsec.conf`/starter workflow, not a full `swanctl`
  deployment.
