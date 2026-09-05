# Contributing

Thanks for improving this project. Keep changes small, testable, and explicit
about operational impact.

## Development

Run the full local check suite before opening a pull request:

```sh
make check
```

`make check` is local-only. It validates rendering, marker integrity, atomic
file restore, rollback behavior, JSON automation input, and preflight checks
without installing packages, writing `/etc`, or restarting a real daemon.

`make integration` builds a Debian container that installs strongSwan starter,
applies a PSK client connection, validates it with `ipsec`, and removes it.
It requires Docker and `NET_ADMIN`; CI runs this target. Run it before changing
rendered configuration, service handling, package behavior, or transactions.

## Pull Requests

Include the following when relevant:

- the target distribution and strongSwan version;
- the connection type affected;
- sample generated config with secrets redacted;
- rollback or failure behavior tested;
- any manual validation performed on a real host.

Do not commit real VPN credentials, private keys, certificates containing private
material, public IPs that should remain private, or production tunnel names.
