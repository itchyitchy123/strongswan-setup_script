# Contributing

Thanks for improving this project. Keep changes small, testable, and explicit
about operational impact.

## Development

Run the full local check suite before opening a pull request:

```sh
make check
```

The tests are intentionally local-only. They validate rendering, marker
integrity, atomic file restore, and rollback behavior without installing
packages, writing `/etc`, or restarting a real strongSwan daemon.

## Pull Requests

Include the following when relevant:

- the target distribution and strongSwan version;
- the connection type affected;
- sample generated config with secrets redacted;
- rollback or failure behavior tested;
- any manual validation performed on a real host.

Do not commit real VPN credentials, private keys, certificates containing private
material, public IPs that should remain private, or production tunnel names.
