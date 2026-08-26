# Security Policy

This repository contains an installer that writes VPN configuration and secrets.
Treat all changes as security-sensitive.

## Reporting Security Issues

Do not open a public issue with live credentials, private keys, production
topology, or exploitable details. Report privately through GitHub security
advisories when available, or contact the repository owner directly.

## Handling Secrets

- Never commit real pre-shared keys, passwords, private keys, or production
  certificates.
- Redact public IPs, identities, and tunnel names when they reveal private
  infrastructure.
- Use long random PSKs where certificate authentication is not available.
- Keep `/etc/ipsec.secrets` readable only by root.

## Operational Expectations

Before running this installer on a production gateway, review the generated
configuration, confirm firewall policy, and use a maintenance window if existing
tunnels may be affected.
