#!/usr/bin/env bash
# Install strongSwan and interactively create one connection in ipsec.conf.

set -Eeuo pipefail
umask 077

readonly IPSEC_CONF=/etc/ipsec.conf
readonly IPSEC_SECRETS=/etc/ipsec.secrets
WORK_DIR=''

cleanup() {
    if [[ -n $WORK_DIR && -d $WORK_DIR && $WORK_DIR == /tmp/tmp.* ]]; then
        rm -f -- "$WORK_DIR/ipsec.conf" "$WORK_DIR/ipsec.secrets"
        rmdir -- "$WORK_DIR" 2>/dev/null || true
    fi
}

trap cleanup EXIT

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '\n==> %s\n' "$*"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

run_as_root() {
    if (( EUID == 0 )); then
        "$@"
    else
        sudo "$@"
    fi
}

prompt_required() {
    local destination=$1 prompt=$2 value
    while :; do
        read -r -p "$prompt: " value
        [[ -n $value ]] && break
        printf 'A value is required.\n' >&2
    done
    printf -v "$destination" '%s' "$value"
}

prompt_default() {
    local destination=$1 prompt=$2 default=$3 value
    read -r -p "$prompt [$default]: " value
    printf -v "$destination" '%s' "${value:-$default}"
}

prompt_secret() {
    local destination=$1 prompt=$2 first second
    while :; do
        read -r -s -p "$prompt: " first
        printf '\n'
        read -r -s -p "Confirm $prompt: " second
        printf '\n'
        [[ -n $first ]] || { printf 'A value is required.\n' >&2; continue; }
        [[ $first == "$second" ]] && break
        printf 'The values did not match; try again.\n' >&2
    done
    printf -v "$destination" '%s' "$first"
}

confirm() {
    local prompt=$1 answer
    read -r -p "$prompt [y/N]: " answer
    [[ $answer == [Yy] || $answer == [Yy][Ee][Ss] ]]
}

validate_name() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
        die "Connection names may contain only letters, numbers, dots, underscores, and hyphens."
}

validate_plain_value() {
    local label=$1 value=$2
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || die "$label contains a newline."
}

validate_host() {
    [[ $1 =~ ^[A-Za-z0-9._:%-]+$ ]] ||
        die 'The gateway must be a hostname or IP address without spaces.'
}

validate_selector() {
    [[ $2 =~ ^[A-Fa-f0-9.:/,[:space:]-]+$ ]] ||
        die "$1 must contain only IP addresses or CIDR ranges separated by commas."
}

escape_secret() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

detect_installer() {
    if command_exists apt-get; then
        INSTALLER=apt
    elif command_exists dnf; then
        INSTALLER=dnf
    elif command_exists yum; then
        INSTALLER=yum
    else
        die 'Supported package manager not found (apt-get, dnf, or yum required).'
    fi
}

install_strongswan() {
    info "Installing strongSwan with $INSTALLER"
    case $INSTALLER in
        apt)
            run_as_root apt-get update
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                strongswan strongswan-pki libcharon-extra-plugins
            ;;
        dnf)
            run_as_root dnf install -y strongswan
            ;;
        yum)
            run_as_root yum install -y strongswan
            ;;
    esac
}

choose_connection_type() {
    printf '\nConnection type:\n'
    printf '  1) Remote-access client using username/password (EAP-MSCHAPv2)\n'
    printf '  2) Remote-access client using a pre-shared key\n'
    printf '  3) Site-to-site tunnel using a pre-shared key\n'
    while :; do
        read -r -p 'Choose 1, 2, or 3: ' CONNECTION_TYPE
        [[ $CONNECTION_TYPE =~ ^[123]$ ]] && return
        printf 'Please enter 1, 2, or 3.\n' >&2
    done
}

collect_common() {
    prompt_default CONNECTION_NAME 'Connection name' 'my-vpn'
    validate_name "$CONNECTION_NAME"
    prompt_required REMOTE_HOST 'VPN gateway hostname or IP address'
    validate_plain_value 'Gateway' "$REMOTE_HOST"
    validate_host "$REMOTE_HOST"
    prompt_default REMOTE_ID 'Remote identity (often the gateway hostname; use %any if unknown)' "$REMOTE_HOST"
    validate_plain_value 'Remote identity' "$REMOTE_ID"
}

collect_client_eap() {
    prompt_required USERNAME 'VPN username'
    validate_plain_value 'Username' "$USERNAME"
    prompt_secret PASSWORD 'VPN password'
    prompt_default LOCAL_TS 'Local traffic selector' '0.0.0.0/0,::/0'
    validate_selector 'Local traffic selector' "$LOCAL_TS"
    CA_CERT=''
    read -r -p 'CA certificate path (recommended; leave blank to configure later): ' CA_CERT
    [[ -z $CA_CERT || -f $CA_CERT ]] || die "CA certificate not found: $CA_CERT"
}

collect_client_psk() {
    prompt_default LOCAL_ID 'Local identity' '%any'
    validate_plain_value 'Local identity' "$LOCAL_ID"
    prompt_secret PSK 'Pre-shared key'
    prompt_default LOCAL_TS 'Traffic selector' '0.0.0.0/0,::/0'
    validate_selector 'Traffic selector' "$LOCAL_TS"
}

collect_site_to_site() {
    prompt_required LOCAL_ID 'Local IKE identity (hostname or public IP)'
    prompt_required LOCAL_SUBNET 'Local protected subnet (for example 10.10.0.0/24)'
    prompt_required REMOTE_SUBNET 'Remote protected subnet (for example 10.20.0.0/24)'
    validate_plain_value 'Local identity' "$LOCAL_ID"
    validate_plain_value 'Local subnet' "$LOCAL_SUBNET"
    validate_plain_value 'Remote subnet' "$REMOTE_SUBNET"
    validate_selector 'Local protected subnet' "$LOCAL_SUBNET"
    validate_selector 'Remote protected subnet' "$REMOTE_SUBNET"
    prompt_secret PSK 'Pre-shared key'
}

render_connection() {
    case $CONNECTION_TYPE in
        1)
            cat <<EOF

conn $CONNECTION_NAME
    keyexchange=ikev2
    type=tunnel
    auto=start
    left=%defaultroute
    leftsourceip=%config
    leftauth=eap-mschapv2
    leftid="$(escape_secret "$USERNAME")"
    right=$REMOTE_HOST
    rightid="$(escape_secret "$REMOTE_ID")"
    rightauth=pubkey
    rightsubnet=$LOCAL_TS
    eap_identity="$(escape_secret "$USERNAME")"
    dpdaction=restart
    closeaction=restart
EOF
            ;;
        2)
            cat <<EOF

conn $CONNECTION_NAME
    keyexchange=ikev2
    type=tunnel
    auto=start
    left=%defaultroute
    leftid="$(escape_secret "$LOCAL_ID")"
    leftauth=psk
    leftsourceip=%config
    right=$REMOTE_HOST
    rightid="$(escape_secret "$REMOTE_ID")"
    rightauth=psk
    rightsubnet=$LOCAL_TS
    dpdaction=restart
    closeaction=restart
EOF
            ;;
        3)
            cat <<EOF

conn $CONNECTION_NAME
    keyexchange=ikev2
    type=tunnel
    auto=start
    left=%defaultroute
    leftid="$(escape_secret "$LOCAL_ID")"
    leftsubnet=$LOCAL_SUBNET
    leftauth=psk
    right=$REMOTE_HOST
    rightid="$(escape_secret "$REMOTE_ID")"
    rightsubnet=$REMOTE_SUBNET
    rightauth=psk
    dpdaction=restart
    closeaction=restart
EOF
            ;;
    esac
}

render_secret() {
    case $CONNECTION_TYPE in
        1) printf '"%s" : EAP "%s"\n' "$(escape_secret "$USERNAME")" "$(escape_secret "$PASSWORD")" ;;
        2|3) printf '"%s" "%s" : PSK "%s"\n' "$(escape_secret "$LOCAL_ID")" \
            "$(escape_secret "$REMOTE_ID")" "$(escape_secret "$PSK")" ;;
    esac
}

without_managed_block() {
    local source=$1 name=$2
    awk -v begin="# BEGIN $name" -v end="# END $name" '
        $0 == begin { skip=1; next }
        $0 == end { skip=0; next }
        !skip { print }
    ' "$source"
}

install_configuration() {
    local new_conf new_secrets timestamp
    WORK_DIR=$(mktemp -d)
    new_conf=$WORK_DIR/ipsec.conf
    new_secrets=$WORK_DIR/ipsec.secrets

    if [[ -r $IPSEC_CONF ]]; then
        without_managed_block "$IPSEC_CONF" "$CONNECTION_NAME" >"$new_conf"
    else
        printf 'config setup\n    uniqueids=no\n\n' >"$new_conf"
    fi
    {
        printf '# BEGIN %s\n' "$CONNECTION_NAME"
        render_connection
        printf '# END %s\n' "$CONNECTION_NAME"
    } >>"$new_conf"

    if [[ -r $IPSEC_SECRETS ]]; then
        without_managed_block "$IPSEC_SECRETS" "$CONNECTION_NAME" >"$new_secrets"
    else
        : >"$new_secrets"
    fi
    {
        printf '# BEGIN %s\n' "$CONNECTION_NAME"
        render_secret
        printf '# END %s\n' "$CONNECTION_NAME"
    } >>"$new_secrets"

    printf '\nThe connection block that will be installed:\n'
    sed -n "/^# BEGIN $CONNECTION_NAME$/,/^# END $CONNECTION_NAME$/p" "$new_conf"
    confirm 'Write this configuration?' || die 'Cancelled; no configuration was changed.'

    timestamp=$(date +%Y%m%d-%H%M%S)
    [[ ! -e $IPSEC_CONF ]] || run_as_root cp -a "$IPSEC_CONF" "$IPSEC_CONF.backup-$timestamp"
    [[ ! -e $IPSEC_SECRETS ]] || run_as_root cp -a "$IPSEC_SECRETS" "$IPSEC_SECRETS.backup-$timestamp"
    run_as_root install -o root -g root -m 0644 "$new_conf" "$IPSEC_CONF"
    run_as_root install -o root -g root -m 0600 "$new_secrets" "$IPSEC_SECRETS"

    if [[ -n ${CA_CERT:-} ]]; then
        run_as_root install -d -o root -g root -m 0755 /etc/ipsec.d/cacerts
        run_as_root install -o root -g root -m 0644 "$CA_CERT" "/etc/ipsec.d/cacerts/${CA_CERT##*/}"
    fi
}

start_and_check() {
    info 'Restarting strongSwan'
    if command_exists systemctl; then
        run_as_root systemctl enable --now strongswan-starter 2>/dev/null ||
            run_as_root systemctl enable --now strongswan
        run_as_root systemctl restart strongswan-starter 2>/dev/null ||
            run_as_root systemctl restart strongswan
    else
        run_as_root ipsec restart
    fi

    info 'Checking the loaded connection'
    if ! run_as_root ipsec statusall | grep -Fq "$CONNECTION_NAME"; then
        die "strongSwan started, but '$CONNECTION_NAME' was not loaded. Check the service logs and timestamped backups."
    fi
}

main() {
    [[ -t 0 ]] || die 'This installer is interactive and must be run from a terminal.'
    (( EUID == 0 )) || command_exists sudo || die 'Run as root or install sudo first.'

    printf 'strongSwan interactive installer\n'
    printf 'This will install packages and update %s and %s.\n' "$IPSEC_CONF" "$IPSEC_SECRETS"
    detect_installer
    install_strongswan
    choose_connection_type
    collect_common
    case $CONNECTION_TYPE in
        1) collect_client_eap ;;
        2) collect_client_psk ;;
        3) collect_site_to_site ;;
    esac
    install_configuration
    start_and_check

    info 'Setup complete'
    printf 'Connection: %s\n' "$CONNECTION_NAME"
    printf 'Status:     sudo ipsec statusall\n'
    printf 'Connect:    sudo ipsec up %s\n' "$CONNECTION_NAME"
    printf 'Disconnect: sudo ipsec down %s\n' "$CONNECTION_NAME"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
