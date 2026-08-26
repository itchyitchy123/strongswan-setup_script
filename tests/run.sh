#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/install-strongswan.sh"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local haystack=$1 needle=$2
    [[ $haystack == *"$needle"* ]] || fail "expected output to contain: $needle"
}

test_psk_percent_identity_rendering() {
    local output
    CONNECTION_TYPE=2
    CONNECTION_NAME=my-vpn
    REMOTE_HOST=vpn.example.com
    REMOTE_ID=%any
    LOCAL_ID=%any
    LOCAL_TS='0.0.0.0/0,::/0'
    PSK='a "quoted" secret'

    output=$(render_connection; render_secret)

    assert_contains "$output" 'leftid=%any'
    assert_contains "$output" 'rightid=%any'
    assert_contains "$output" '%any %any : PSK "a \"quoted\" secret"'
    assert_contains "$output" 'dpdtimeout=120s'
}

test_eap_identity_rendering() {
    local output
    CONNECTION_TYPE=1
    CONNECTION_NAME=eap-vpn
    REMOTE_HOST=vpn.example.com
    REMOTE_ID=vpn.example.com
    USERNAME='alice@example.com'
    PASSWORD='secret'
    LOCAL_TS='0.0.0.0/0'

    output=$(render_connection; render_secret)

    assert_contains "$output" 'leftid="alice@example.com"'
    assert_contains "$output" 'rightid="vpn.example.com"'
    assert_contains "$output" '"alice@example.com" : EAP "secret"'
    assert_contains "$output" 'mobike=yes'
}

test_selector_validation_rejects_bad_cidr() {
    local stderr
    stderr=$(validate_selector 'Traffic selector' '10.0.0.0/999' 2>&1 >/dev/null) &&
        fail 'invalid CIDR was accepted'
    assert_contains "$stderr" 'invalid CIDR selector'
}

test_managed_block_replacement() {
    local tmp output
    tmp=$(mktemp)
    trap 'rm -f -- "$tmp"' RETURN
    {
        printf 'keep-before\n'
        printf '# BEGIN my-vpn\n'
        printf 'old-block\n'
        printf '# END my-vpn\n'
        printf 'keep-after\n'
    } >"$tmp"

    output=$(without_managed_block "$tmp" my-vpn)
    [[ $output == $'keep-before\nkeep-after' ]] ||
        fail "managed block was not removed cleanly: $output"
}

test_psk_percent_identity_rendering
test_eap_identity_rendering
test_selector_validation_rejects_bad_cidr
test_managed_block_replacement

printf 'All tests passed.\n'
