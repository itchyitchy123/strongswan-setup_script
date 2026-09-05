# strongSwan setup

`strongswan-setup` is a small, auditable Go program for installing one IKEv2 connection through strongSwan's legacy `ipsec.conf`/starter backend. It is intended for managed Linux clients and policy-based site-to-site tunnels.

It refuses hosts running the modern `strongswan.service`/`swanctl` backend. That is deliberate: `ipsec.conf` (stroke) is deprecated upstream and must not be mixed with `swanctl.conf`/VICI on the same host. Use this program only where the distribution's legacy starter service is the selected backend.

## What it protects

- Atomic configuration replacement and a root-only transaction lock.
- Root-only secret files and root-only, bounded backup snapshots.
- Rollback of files **and daemon state** when validation, restart, loading, or an optional health check fails.
- An exact remote IKE identity by default; `%any` requires an explicit unsafe override.
- An explicit acknowledgement before a full-tunnel selector can be used.
- Certificate parsing, SHA-256 fingerprint display, and collision-resistant CA storage names.
- Strict input validation, secure IKE/ESP defaults, explicit lifetimes, and EAP plugin checks.

The generated connection defaults to `auto=add`, so it does not unexpectedly take over traffic. `--start` is required to bring it up immediately.

## Build

```sh
make check
make build
sudo install -o root -g root -m 0755 bin/strongswan-setup /usr/local/sbin/strongswan-setup
```

The project uses only the Go standard library. CI runs formatting, vetting, unit
tests, and a Debian container smoke test against a real strongSwan starter
daemon. See [operations documentation](docs/OPERATIONS.md) for the complete
command reference and recovery procedures.

## Automation and lifecycle

Use `--config connection.json` for configuration management; command-line flags
override file values. JSON deliberately accepts secret **file paths**, not secret
values. Add `--output json` for a machine-readable completion result.

```json
{
  "profile": "psk-client",
  "name": "office",
  "gateway": "vpn.example.net",
  "remote_id": "vpn.example.net",
  "remote_ts": "10.20.0.0/16",
  "psk_file": "/run/secrets/office.psk",
  "non_interactive": true,
  "yes": true
}
```

Run `--check` with the normal connection inputs to report DNS, route, legacy
backend, forwarding, reverse-path-filter, and XFRM-interface readiness without
writing files. Use `--list` to discover managed connections, `--remove --name
NAME --yes` to remove one transactionally, and `--rollback TRANSACTION --yes`
to restore a prior transaction. Removal retains copied CA certificates because
they can be shared by other connections.

## Safe noninteractive example

Provide secrets through your deployment system's protected mechanism, not a shell history or a process list. `--psk-file` and `--password-file` accept a regular file that is mode `0600` or stricter; one final newline is removed. Omit these flags for hidden interactive entry.

```sh
sudo strongswan-setup \
  --non-interactive --yes --install-packages \
  --profile site-to-site --name branch-a \
  --gateway vpn.example.net --remote-id vpn.example.net \
  --local-id branch-a.example.net \
  --local-ts 10.10.0.0/24 --remote-ts 10.20.0.0/24 \
  --psk-file /run/secrets/branch-a.psk
```

For an EAP client, use `--profile eap`, `--username`, `--password-file`, `--ca-cert /secure/path/ca.pem`, and the expected `--remote-id`. A CA is required unless `--use-system-ca` is deliberately selected. Confirm the shown certificate fingerprint with the VPN administrator.

For a full-tunnel client, provide `--remote-ts '0.0.0.0/0,::/0'` and `--full-tunnel`. Schedule this change: full tunnelling can alter an active SSH or management path.

Start and verify only after the configuration is installed:

```sh
sudo ipsec up branch-a
sudo ipsec statusall
```

Or add `--start --probe-host 10.20.0.10:443` to require an IKE SA and a TCP probe before the program reports success.

## Operational model

Before writing files, the program checks the gateway resolves, the local host has a route to it, the legacy `ipsec` command is available, and (for EAP) that the EAP-MSCHAPv2 plugin is loaded. It prints a plan without secrets and asks for a final confirmation unless `--yes` is passed. `--dry-run` performs only local rendering and validation; it changes no files, packages, or services.

It intentionally does **not** create firewall, NAT, forwarding, DNS, or route policy. Those choices depend on the topology. Before production use, confirm:

- UDP 500 and 4500 are allowed in every relevant firewall/security group.
- NAT traversal, return routes, and source-NAT exemptions are correct.
- Kernel XFRM support and system time synchronization are healthy.
- Site-to-site gateways have forwarding enabled and explicit firewall rules.
- The approved IKE/ESP suites match the peer. Override `--ike` and `--esp` only with organization-approved proposals.

The program validates with `ipsec checkconfig`, restarts the selected legacy service, confirms the connection is loaded, and restores both files and the prior daemon state on failure. Backups are stored in `/var/backups/strongswan-setup` with mode `0700`; only the newest ten transactions are retained. The transaction lock uses an advisory kernel lock, so it is released automatically after a crash. Backup files contain previous secrets and must be protected accordingly.

## Scope and limitations

This is deliberately not a general VPN orchestrator. It supports EAP-MSCHAPv2 clients, PSK clients, and PSK site-to-site tunnels. It does not issue or rotate certificates, create firewall rules, manage route-based/XFRM-interface VPNs, or configure a modern `swanctl.conf` deployment. For new or complex production deployments, use `swanctl`/VICI with configuration management.
