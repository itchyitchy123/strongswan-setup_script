# Operations guide

## Supported backend

This tool manages one connection in the legacy strongSwan starter backend:
`/etc/ipsec.conf`, `/etc/ipsec.secrets`, and the `ipsec` command. It refuses a
host whose `strongswan.service` is configured for the modern `swanctl` backend.
Do not use it to manage `swanctl.conf`, NetworkManager connections, Libreswan,
or Openswan.

The tool verifies that `ipsec --version` identifies strongSwan before it writes
configuration. `--install-packages` supports `apt-get`, `dnf`, and `yum`; it
first refuses a detected modern-backend host to prevent mixing backends.

## Profiles

| Profile | Required inputs | Generated behavior |
| --- | --- | --- |
| `eap` | `--username`, `--password-file` or hidden prompt, `--ca-cert` (or explicit `--use-system-ca`), `--remote-ts` | IKEv2 EAP-MSCHAPv2 client with a requested virtual IP. |
| `psk-client` | `--psk-file` or hidden prompt, `--remote-ts` | IKEv2 PSK client with a requested virtual IP. |
| `site-to-site` | `--local-id`, `--psk-file` or hidden prompt, `--local-ts`, `--remote-ts` | Policy-based IKEv2 PSK tunnel with MOBIKE disabled. IPv4 forwarding must already be enabled. |

Every profile requires `--name`, `--gateway`, and an exact `--remote-id`.
`%any` as a remote identity is rejected unless `--allow-any-remote-id` is
specified. Full-tunnel selectors require `--full-tunnel` in addition to
`0.0.0.0/0` and/or `::/0`.

## Safe workflow

1. Place the PSK or EAP password in a root-owned regular file mode `0600`.
2. Run `--check` with the intended connection inputs.
3. Run `--dry-run` and review the rendered connection. It never calls package,
   service, or network commands.
4. Apply during a maintenance window. The default is `auto=add`; `--start`
   explicitly starts the tunnel immediately.
5. Check `ipsec statusall` and, when appropriate, specify `--probe-host
   HOST:PORT` with `--start`.

For example:

```sh
sudo strongswan-setup --check --non-interactive \
  --profile site-to-site --name branch-a \
  --gateway vpn.example.net --remote-id vpn.example.net \
  --local-id branch-a.example.net \
  --local-ts 10.10.0.0/24 --remote-ts 10.20.0.0/24 \
  --psk-file /run/secrets/branch-a.psk
```

## Automation

`--config FILE` loads JSON before parsing command-line flags, so explicitly
provided flags override configuration-file values. Configuration files accept
the same fields in `snake_case`, for example `remote_id`, `remote_ts`,
`psk_file`, `non_interactive`, `install_packages`, and `full_tunnel`.

Use secret-file fields (`psk_file` and `password_file`) rather than secret
values. The supported JSON fields are: `profile`, `name`, `gateway`,
`remote_id`, `local_id`, `username`, `password_file`, `psk_file`, `remote_ts`,
`local_ts`, `ca_cert`, `ike`, `esp`, `ipsec_conf`, `ipsec_secrets`, `ca_dir`,
`backup_dir`, `probe_host`, `output`, `non_interactive`, `yes`, `dry_run`,
`check`, `remove`, `list`, `install_packages`, `start`, `full_tunnel`,
`allow_any_remote_id`, and `use_system_ca`.

`--output json` produces a secret-free result record for normal installation
and dry-run actions. Keep the default `text` output for interactive use.

## Diagnostics and network policy

`--check` performs non-mutating gateway DNS, route, starter-backend, strongSwan
identity, EAP-plugin, IP forwarding, reverse-path-filter, and XFRM-interface
checks. It reports unavailable optional host checks as warnings.

The tool does not alter firewall, NAT, routing, DNS, forwarding, or kernel
policy. Operators remain responsible for UDP 500/4500, NAT traversal,
source-NAT exemptions, return routes, kernel XFRM support, clock
synchronization, and site-to-site forwarding policy.

## Lifecycle and recovery

- `--list` prints connections managed by this tool.
- `--remove --name NAME --yes` removes that managed connection and restarts the
  legacy service. It does not remove copied CA files because CAs may be shared.
- Each apply or remove transaction creates a root-only backup directory under
  `/var/backups/strongswan-setup/<transaction-id>/` with a manifest.
- `--rollback TRANSACTION_ID --yes` restores the files described by that
  manifest, validates them, and restarts strongSwan.

Transaction backups include secrets. Do not place them in ticket attachments,
logs, or diagnostic archives.

## Proposal policy

The default IKE proposal is `aes256gcm16-prfsha384-ecp384!`; the default ESP
proposal is `aes256gcm16-ecp384!`. The trailing `!` restricts negotiation to
the configured proposal. Override `--ike` or `--esp` only when the VPN peer and
your organization’s cryptographic policy explicitly require another suite.

## Development checks

```sh
make check        # format, vet, and unit tests
make build        # bin/strongswan-setup
make integration  # Docker-based real strongSwan starter smoke test
```

`make integration` requires Docker and runs the container with `NET_ADMIN`.
