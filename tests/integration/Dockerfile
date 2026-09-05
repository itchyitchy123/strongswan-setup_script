FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan strongswan-pki libcharon-extra-plugins iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY bin/strongswan-setup /usr/local/sbin/strongswan-setup
COPY tests/integration/run.sh /usr/local/libexec/strongswan-setup-integration

RUN chmod 0755 /usr/local/sbin/strongswan-setup /usr/local/libexec/strongswan-setup-integration

ENTRYPOINT ["/usr/local/libexec/strongswan-setup-integration"]
