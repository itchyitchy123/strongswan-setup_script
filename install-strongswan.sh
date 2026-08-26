#!/usr/bin/env bash
# Install strongSwan and interactively create one connection in ipsec.conf.

set -Eeuo pipefail
umask 077

readonly IPSEC_CONF=/etc/ipsec.conf
readonly IPSEC_SECRETS=/etc/ipsec.secrets
WORK_DIR=''
BACKUP_CONF=''
BACKUP_SECRETS=''
BACKUP_CA_CERT=''
CA_CERT_TARGET=''
HAD_IPSEC_CONF=0
HAD_IPSEC_SECRETS=0
HAD_CA_CERT=0

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
    [[ $value != *'#'* ]] || die "$label may not contain '#'."
}

validate_host() {
    [[ $1 =~ ^[A-Za-z0-9._:%-]+$ ]] ||
        die 'The gateway must be a hostname or IP address without spaces.'
}

validate_selector() {
    local label=$1 value=$2
    [[ $value =~ ^[A-Fa-f0-9.:/,[:space:]-]+$ ]] ||
        die "$1 must contain only IP addresses or CIDR ranges separated by commas."
    if command_exists python3; then
        python3 - "$label" "$value" <<'PY' || exit 1
import ipaddress
import sys

label, raw = sys.argv[1], sys.argv[2]
parts = [part.strip() for part in raw.split(",")]
if not parts or any(not part for part in parts):
    print(f"Error: {label} contains an empty traffic selector.", file=sys.stderr)
    sys.exit(1)
for part in parts:
    try:
        ipaddress.ip_network(part, strict=False)
    except ValueError as exc:
        print(f"Error: {label} contains invalid CIDR selector {part!r}: {exc}", file=sys.stderr)
        sys.exit(1)
PY
    fi
}

escape_secret() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

is_special_identity() {
    [[ $1 =~ ^%[A-Za-z0-9_.:-]+$ ]]
}

render_identity() {
    local value=$1
    if is_special_identity "$value"; then
        printf '%s' "$value"
    else
        printf '"%s"' "$(escape_secret "$value")"
    fi
}

validate_ca_cert() {
    local path=$1
    [[ -f $path ]] || die "CA certificate not found: $path"
    if command_exists openssl; then
        openssl x509 -in "$path" -noout >/dev/null 2>&1 ||
            die "CA certificate is not a parseable X.509 certificate: $path"
    fi
}

existing_ca_certs_present() {
    compgen -G '/etc/ipsec.d/cacerts/*' >/dev/null 2>&1
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
    if existing_ca_certs_present; then
        read -r -p 'CA certificate path (leave blank to use existing /etc/ipsec.d/cacerts): ' CA_CERT
    else
        prompt_required CA_CERT 'CA certificate path for server certificate validation'
    fi
    [[ -z $CA_CERT ]] || validate_ca_cert "$CA_CERT"
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
    leftid=$(render_identity "$USERNAME")
    right=$REMOTE_HOST
    rightid=$(render_identity "$REMOTE_ID")
    rightauth=pubkey
    rightsubnet=$LOCAL_TS
    eap_identity=$(render_identity "$USERNAME")
    fragmentation=yes
    mobike=yes
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
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
    leftid=$(render_identity "$LOCAL_ID")
    leftauth=psk
    leftsourceip=%config
    right=$REMOTE_HOST
    rightid=$(render_identity "$REMOTE_ID")
    rightauth=psk
    rightsubnet=$LOCAL_TS
    fragmentation=yes
    mobike=yes
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
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
    leftid=$(render_identity "$LOCAL_ID")
    leftsubnet=$LOCAL_SUBNET
    leftauth=psk
    right=$REMOTE_HOST
    rightid=$(render_identity "$REMOTE_ID")
    rightsubnet=$REMOTE_SUBNET
    rightauth=psk
    fragmentation=yes
    mobike=no
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    closeaction=restart
EOF
            ;;
    esac
}

render_secret() {
    case $CONNECTION_TYPE in
        1) printf '%s : EAP "%s"\n' "$(render_identity "$USERNAME")" "$(escape_secret "$PASSWORD")" ;;
        2|3) printf '%s %s : PSK "%s"\n' "$(render_identity "$LOCAL_ID")" \
            "$(render_identity "$REMOTE_ID")" "$(escape_secret "$PSK")" ;;
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
    BACKUP_CONF=''
    BACKUP_SECRETS=''
    BACKUP_CA_CERT=''
    CA_CERT_TARGET=''
    HAD_IPSEC_CONF=0
    HAD_IPSEC_SECRETS=0
    HAD_CA_CERT=0
    if [[ -e $IPSEC_CONF ]]; then
        HAD_IPSEC_CONF=1
        BACKUP_CONF=$IPSEC_CONF.backup-$timestamp
        run_as_root cp -a "$IPSEC_CONF" "$BACKUP_CONF"
    fi
    if [[ -e $IPSEC_SECRETS ]]; then
        HAD_IPSEC_SECRETS=1
        BACKUP_SECRETS=$IPSEC_SECRETS.backup-$timestamp
        run_as_root cp -a "$IPSEC_SECRETS" "$BACKUP_SECRETS"
    fi
    run_as_root install -o root -g root -m 0644 "$new_conf" "$IPSEC_CONF"
    run_as_root install -o root -g root -m 0600 "$new_secrets" "$IPSEC_SECRETS"

    if [[ -n ${CA_CERT:-} ]]; then
        CA_CERT_TARGET=/etc/ipsec.d/cacerts/${CA_CERT##*/}
        run_as_root install -d -o root -g root -m 0755 /etc/ipsec.d/cacerts
        if [[ -e $CA_CERT_TARGET ]]; then
            HAD_CA_CERT=1
            BACKUP_CA_CERT=$CA_CERT_TARGET.backup-$timestamp
            run_as_root cp -a "$CA_CERT_TARGET" "$BACKUP_CA_CERT"
        fi
        run_as_root install -o root -g root -m 0644 "$CA_CERT" "$CA_CERT_TARGET"
    fi
}

restore_backups() {
    info 'Restoring previous strongSwan configuration'
    if [[ -n $BACKUP_CONF && -e $BACKUP_CONF ]]; then
        run_as_root install -o root -g root -m 0644 "$BACKUP_CONF" "$IPSEC_CONF"
    elif (( HAD_IPSEC_CONF == 0 )); then
        run_as_root rm -f -- "$IPSEC_CONF"
    fi
    if [[ -n $BACKUP_SECRETS && -e $BACKUP_SECRETS ]]; then
        run_as_root install -o root -g root -m 0600 "$BACKUP_SECRETS" "$IPSEC_SECRETS"
    elif (( HAD_IPSEC_SECRETS == 0 )); then
        run_as_root rm -f -- "$IPSEC_SECRETS"
    fi
    if [[ -n $CA_CERT_TARGET ]]; then
        if [[ -n $BACKUP_CA_CERT && -e $BACKUP_CA_CERT ]]; then
            run_as_root install -o root -g root -m 0644 "$BACKUP_CA_CERT" "$CA_CERT_TARGET"
        elif (( HAD_CA_CERT == 0 )); then
            run_as_root rm -f -- "$CA_CERT_TARGET"
        fi
    fi
}

run_or_rollback() {
    local message=$1
    shift
    if ! "$@"; then
        restore_backups
        die "$message"
    fi
}

validate_installed_configuration() {
    if command_exists ipsec && run_as_root ipsec --help 2>&1 | grep -Fq checkconfig; then
        info 'Validating strongSwan configuration'
        run_as_root ipsec checkconfig
    fi
}

detect_systemd_unit() {
    local unit
    for unit in strongswan-starter.service strongswan.service ipsec.service; do
        if run_as_root systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -Fq "$unit"; then
            printf '%s\n' "$unit"
            return 0
        fi
    done
    return 1
}

start_and_check() {
    local unit
    run_or_rollback 'Installed strongSwan configuration failed validation; restored previous files.' \
        validate_installed_configuration

    info 'Restarting strongSwan'
    if command_exists systemctl && unit=$(detect_systemd_unit); then
        run_or_rollback "Failed to enable/start $unit; restored previous files." \
            run_as_root systemctl enable --now "$unit"
        run_or_rollback "Failed to restart $unit; restored previous files." \
            run_as_root systemctl restart "$unit"
    elif command_exists ipsec; then
        run_or_rollback 'Failed to restart strongSwan with ipsec; restored previous files.' \
            run_as_root ipsec restart
    else
        run_or_rollback 'Could not find systemctl unit or ipsec command; restored previous files.' false
    fi

    info 'Checking the loaded connection'
    if ! run_as_root ipsec statusall | grep -Fq "$CONNECTION_NAME"; then
        restore_backups
        die "strongSwan started, but '$CONNECTION_NAME' was not loaded. Previous configuration was restored."
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
