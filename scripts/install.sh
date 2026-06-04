#!/usr/bin/env bash
set -euo pipefail

REPO_SLUG="${KIDOBO_REPO_SLUG:-blwarren/kidobo}"
INSTALL_DIR="${KIDOBO_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="kidobo"
KIDOBO_CHAIN_NAME="kidobo-input"
DEFAULT_SET_NAME="kidobo"
DEFAULT_SET_NAME_V6="kidobo-v6"
KIDOBO_ROOT_OVERRIDE="${KIDOBO_ROOT:-}"
INIT_AFTER_INSTALL=0
UNINSTALL_ONLY=0
VERSION=""
TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"

usage() {
    cat <<'EOF'
Usage:
  scripts/install.sh [--version vX.Y.Z] [--init]
  scripts/install.sh --uninstall

Options:
  --version vX.Y.Z  Install a specific release tag. Defaults to latest.
  --init            Run `kidobo init` after installing the binary.
  --uninstall       Remove kidobo binary and runtime artifacts.
  -h, --help        Show this help.

Environment:
  KIDOBO_REPO_SLUG   Override GitHub repo slug (default: blwarren/kidobo)
  KIDOBO_INSTALL_DIR Override install path (default: /usr/local/bin)
  KIDOBO_ROOT        Override runtime artifact root (matches `kidobo init`)
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

run_with_optional_sudo() {
    if "$@"; then
        return 0
    fi

    if [[ "${EUID}" -eq 0 ]]; then
        return 1
    fi

    if has_cmd sudo; then
        sudo -n "$@"
        return $?
    fi

    return 1
}

run_with_init_privileges() {
    if [[ -w /etc || -w /var || -w /usr ]]; then
        "$@"
        return $?
    fi

    if has_cmd sudo; then
        sudo "$@"
        return $?
    fi

    return 1
}

run_init_after_install() {
    local init_log="$1"
    : > "${init_log}"

    if [[ -w /etc || -w /var || -w /usr ]]; then
        if "${TARGET_PATH}" init > >(tee "${init_log}") 2>&1; then
            return 0
        fi
        return $?
    elif has_cmd sudo; then
        if sudo "${TARGET_PATH}" init > >(tee "${init_log}") 2>&1; then
            return 0
        fi
        return $?
    else
        echo "skipping init: insufficient privileges and sudo unavailable" >&2
        return 1
    fi
}

recover_known_init_systemd_reset_failed_case() {
    local init_log="$1"

    if [[ -n "${KIDOBO_ROOT_OVERRIDE}" ]]; then
        return 1
    fi

    if ! has_cmd systemctl; then
        return 1
    fi

    if ! grep -Fq 'systemctl reset-failed kidobo-sync.service' "${init_log}"; then
        return 1
    fi

    if ! grep -Fq 'Unit kidobo-sync.service not loaded' "${init_log}"; then
        return 1
    fi

    echo "detected known systemd reset-failed condition; continuing with timer enablement"
    if ! run_with_init_privileges systemctl daemon-reload; then
        echo "failed to reload systemd daemon during init recovery" >&2
        return 1
    fi

    if ! run_with_init_privileges systemctl reset-failed kidobo-sync.service >/dev/null 2>&1; then
        echo "warning: failed to reset failed state for kidobo-sync.service during init recovery" >&2
    fi

    if ! run_with_init_privileges systemctl enable --now kidobo-sync.timer; then
        echo "failed to enable kidobo-sync.timer during init recovery" >&2
        return 1
    fi

    echo "recovered from init reset-failed error"
    return 0
}

resolve_latest_tag() {
    local latest_url
    latest_url="$(
        curl -fsSL -o /dev/null -w '%{url_effective}' \
            "https://github.com/${REPO_SLUG}/releases/latest"
    )"

    local tag="${latest_url##*/}"
    if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
        echo "failed to resolve latest release tag from: ${latest_url}" >&2
        exit 1
    fi

    echo "${tag}"
}

install_file() {
    local source_file="$1"
    local target_file="$2"

    if [[ -w "$(dirname "${target_file}")" ]]; then
        install -m 0755 "${source_file}" "${target_file}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo install -m 0755 "${source_file}" "${target_file}"
    else
        echo "no write access to $(dirname "${target_file}") and sudo is unavailable" >&2
        exit 1
    fi
}

remove_path() {
    local target_path="$1"
    local label="$2"

    if [[ -e "${target_path}" || -L "${target_path}" ]]; then
        echo "removing ${label}: ${target_path}"
        if run_with_optional_sudo rm -rf -- "${target_path}"; then
            echo "removed ${target_path}"
        else
            echo "failed to remove ${target_path}" >&2
            exit 1
        fi
    else
        echo "${label} not found at ${target_path}"
    fi
}

warn_best_effort() {
    local description="$1"
    shift

    if run_with_optional_sudo "$@" >/dev/null 2>&1; then
        return 0
    fi

    echo "warning: failed to ${description}" >&2
}

resolve_uninstall_paths() {
    if [[ -n "${KIDOBO_ROOT_OVERRIDE}" ]]; then
        if [[ "${KIDOBO_ROOT_OVERRIDE}" == "/" ]]; then
            echo "refusing uninstall with KIDOBO_ROOT=/" >&2
            exit 1
        fi

        CONFIG_DIR="${KIDOBO_ROOT_OVERRIDE}/config"
        DATA_DIR="${KIDOBO_ROOT_OVERRIDE}/data"
        CACHE_DIR="${KIDOBO_ROOT_OVERRIDE}/cache"
        SYSTEMD_DIR="${KIDOBO_ROOT_OVERRIDE}/systemd/system"
    else
        CONFIG_DIR="/etc/kidobo"
        DATA_DIR="/var/lib/kidobo"
        CACHE_DIR="/var/cache/kidobo"
        SYSTEMD_DIR="/etc/systemd/system"
    fi

    SYSTEMD_SERVICE_PATH="${SYSTEMD_DIR}/kidobo-sync.service"
    SYSTEMD_TIMER_PATH="${SYSTEMD_DIR}/kidobo-sync.timer"
}

run_flush_best_effort() {
    if [[ ! -x "${TARGET_PATH}" ]]; then
        echo "${BINARY_NAME} binary not found at ${TARGET_PATH}; skipping flush command"
        return 1
    fi

    echo "running ${BINARY_NAME} flush (best effort)"
    if [[ -n "${KIDOBO_ROOT_OVERRIDE}" ]]; then
        if "${TARGET_PATH}" flush; then
            return 0
        fi
    elif [[ "${EUID}" -eq 0 ]]; then
        if "${TARGET_PATH}" flush; then
            return 0
        fi
    elif has_cmd sudo; then
        if sudo -n "${TARGET_PATH}" flush; then
            return 0
        fi
    elif "${TARGET_PATH}" flush; then
        return 0
    fi

    echo "warning: ${BINARY_NAME} flush failed; continuing with direct fallback cleanup" >&2
    return 1
}

cleanup_firewall_chain_family() {
    local binary="$1"
    if ! has_cmd "${binary}"; then
        echo "warning: ${binary} is unavailable; skipping direct firewall cleanup for ${KIDOBO_CHAIN_NAME}" >&2
        return
    fi

    while run_with_optional_sudo "${binary}" -D INPUT -j "${KIDOBO_CHAIN_NAME}" >/dev/null 2>&1; do
        :
    done

    warn_best_effort "flush ${binary} chain ${KIDOBO_CHAIN_NAME}" \
        "${binary}" -F "${KIDOBO_CHAIN_NAME}"
    warn_best_effort "delete ${binary} chain ${KIDOBO_CHAIN_NAME}" \
        "${binary}" -X "${KIDOBO_CHAIN_NAME}"
}

cleanup_default_ipsets() {
    if ! has_cmd ipset; then
        echo "warning: ipset is unavailable; skipping default ipset cleanup" >&2
        return
    fi

    warn_best_effort "destroy ipset ${DEFAULT_SET_NAME}" ipset destroy "${DEFAULT_SET_NAME}"
    warn_best_effort "destroy ipset ${DEFAULT_SET_NAME_V6}" ipset destroy "${DEFAULT_SET_NAME_V6}"
}

disable_systemd_timer_best_effort() {
    if [[ -n "${KIDOBO_ROOT_OVERRIDE}" ]]; then
        return
    fi

    if ! has_cmd systemctl; then
        echo "warning: systemctl is unavailable; skipping timer disable/reset" >&2
        return
    fi

    warn_best_effort "disable kidobo-sync.timer" \
        systemctl disable --now kidobo-sync.timer
    warn_best_effort "reset failed state for kidobo-sync.service" \
        systemctl reset-failed kidobo-sync.service
}

reload_systemd_best_effort() {
    if [[ -n "${KIDOBO_ROOT_OVERRIDE}" ]]; then
        return
    fi

    if ! has_cmd systemctl; then
        return
    fi

    warn_best_effort "reload systemd daemon" systemctl daemon-reload
}

uninstall_artifacts() {
    require_cmd rm
    resolve_uninstall_paths

    echo "uninstalling ${BINARY_NAME} artifacts"

    if ! run_flush_best_effort; then
        cleanup_firewall_chain_family iptables
        cleanup_firewall_chain_family ip6tables
        cleanup_default_ipsets
    fi

    disable_systemd_timer_best_effort
    remove_path "${SYSTEMD_TIMER_PATH}" "systemd timer"
    remove_path "${SYSTEMD_SERVICE_PATH}" "systemd service"
    reload_systemd_best_effort

    remove_path "${CACHE_DIR}" "cache dir"
    remove_path "${DATA_DIR}" "data dir"
    remove_path "${CONFIG_DIR}" "config dir"
    remove_path "${TARGET_PATH}" "binary"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            if [[ $# -lt 2 ]]; then
                echo "missing value for --version" >&2
                exit 1
            fi
            VERSION="$2"
            shift
            ;;
        --init)
            INIT_AFTER_INSTALL=1
            ;;
        --uninstall)
            UNINSTALL_ONLY=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [[ "${UNINSTALL_ONLY}" -eq 1 && ( -n "${VERSION}" || "${INIT_AFTER_INSTALL}" -eq 1 ) ]]; then
    echo "--uninstall cannot be combined with --version or --init" >&2
    exit 1
fi

if [[ "${UNINSTALL_ONLY}" -eq 1 ]]; then
    uninstall_artifacts
    exit 0
fi

require_cmd curl
require_cmd tar
require_cmd sha256sum
require_cmd install

if [[ -z "${VERSION}" ]]; then
    VERSION="$(resolve_latest_tag)"
fi

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "invalid version tag: ${VERSION}" >&2
    exit 1
fi

ARCHIVE="kidobo-${VERSION}-linux-x86_64.tar.gz"
BASE_URL="https://github.com/${REPO_SLUG}/releases/download/${VERSION}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo "installing ${BINARY_NAME} ${VERSION} from ${REPO_SLUG}"
curl -fsSL -o "${workdir}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl -fsSL -o "${workdir}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

(
    cd "${workdir}"
    expected_line="$(
        awk -v archive="${ARCHIVE}" \
            '$2 == archive { print; found = 1; exit } END { exit (found ? 0 : 1) }' \
            SHA256SUMS || true
    )"
    if [[ -z "${expected_line}" ]]; then
        echo "checksum entry not found for ${ARCHIVE}" >&2
        exit 1
    fi
    echo "${expected_line}" | sha256sum -c -
)

tar -xzf "${workdir}/${ARCHIVE}" -C "${workdir}"
install_file "${workdir}/kidobo-${VERSION}-linux-x86_64/${BINARY_NAME}" "${TARGET_PATH}"

echo "installed ${BINARY_NAME} to ${TARGET_PATH}"
"${TARGET_PATH}" --version

if [[ "${INIT_AFTER_INSTALL}" -eq 1 ]]; then
    echo "running ${BINARY_NAME} init"
    init_log_path="${workdir}/init.log"
    if ! run_init_after_install "${init_log_path}"; then
        if ! recover_known_init_systemd_reset_failed_case "${init_log_path}"; then
            echo "${BINARY_NAME} init failed" >&2
            exit 1
        fi
    fi
fi
