#!/usr/bin/env bash
set -euo pipefail

REPO_SLUG="${KIDOBO_REPO_SLUG:-blwarren/kidobo}"
INSTALL_DIR="${KIDOBO_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="kidobo"
KIDOBO_CHAIN_NAME="kidobo-input"
KIDOBO_STAGING_CHAIN_NAME="kidobo-input-stage"
DEFAULT_SET_NAME="kidobo"
DEFAULT_SET_NAME_V6="kidobo-v6"
KIDOBO_ROOT_WAS_SET="${KIDOBO_ROOT+x}"
KIDOBO_ROOT_OVERRIDE="${KIDOBO_ROOT-}"
INIT_AFTER_INSTALL=0
UNINSTALL_ONLY=0
VERSION=""
TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
STAGED_INSTALL_PATH=""

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
        else
            local status=$?
            return "${status}"
        fi
    elif has_cmd sudo; then
        if sudo "${TARGET_PATH}" init > >(tee "${init_log}") 2>&1; then
            return 0
        else
            local status=$?
            return "${status}"
        fi
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

create_install_staging_path() {
    local target_file="$1"
    local template="${target_file}.tmp.XXXXXX"

    if [[ -w "$(dirname "${target_file}")" ]]; then
        mktemp "${template}"
    elif has_cmd sudo; then
        sudo -n mktemp "${template}"
    else
        echo "no write access to $(dirname "${target_file}") and sudo is unavailable" >&2
        exit 1
    fi
}

stage_install_file() {
    local source_file="$1"
    local target_file="$2"
    STAGED_INSTALL_PATH="$(create_install_staging_path "${target_file}")"

    if ! run_with_optional_sudo install -m 0755 "${source_file}" "${STAGED_INSTALL_PATH}"; then
        echo "failed to stage ${BINARY_NAME} for installation" >&2
        exit 1
    fi
}

activate_staged_install() {
    local target_file="$1"
    if ! run_with_optional_sudo mv -f -- "${STAGED_INSTALL_PATH}" "${target_file}"; then
        echo "failed to atomically install ${BINARY_NAME} at ${target_file}" >&2
        exit 1
    fi
    STAGED_INSTALL_PATH=""
}

cleanup_install_temporary_files() {
    local status=$?
    trap - EXIT
    if [[ -n "${STAGED_INSTALL_PATH}" ]]; then
        run_with_optional_sudo rm -f -- "${STAGED_INSTALL_PATH}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${workdir:-}" ]]; then
        rm -rf -- "${workdir}"
    fi
    exit "${status}"
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
    if [[ -n "${KIDOBO_ROOT_WAS_SET}" ]]; then
        if [[ -z "${KIDOBO_ROOT_OVERRIDE}" ]]; then
            echo "refusing uninstall with an empty KIDOBO_ROOT" >&2
            exit 1
        fi

        require_cmd realpath
        local canonical_root
        if ! canonical_root="$(realpath -m -- "${KIDOBO_ROOT_OVERRIDE}")"; then
            echo "failed to resolve KIDOBO_ROOT: ${KIDOBO_ROOT_OVERRIDE}" >&2
            exit 1
        fi
        if [[ "${canonical_root}" == "/" ]]; then
            echo "refusing uninstall with KIDOBO_ROOT resolving to /" >&2
            exit 1
        fi
        KIDOBO_ROOT_OVERRIDE="${canonical_root}"

        CONFIG_DIR="${KIDOBO_ROOT_OVERRIDE}/config"
        DATA_DIR="${KIDOBO_ROOT_OVERRIDE}/data"
        CACHE_DIR="${KIDOBO_ROOT_OVERRIDE}/cache"
        SYSTEMD_DIR="${KIDOBO_ROOT_OVERRIDE}/systemd/system"

        local scoped_path
        for scoped_path in "${CONFIG_DIR}" "${DATA_DIR}" "${CACHE_DIR}" "${SYSTEMD_DIR}"; do
            if [[ "${scoped_path}" != "${KIDOBO_ROOT_OVERRIDE}/"* ]]; then
                echo "refusing uninstall path outside KIDOBO_ROOT: ${scoped_path}" >&2
                exit 1
            fi
        done
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
        echo "failed to confirm cleanup: ${binary} is unavailable" >&2
        return 1
    fi

    local failed=0
    local chain_name
    local output
    for chain_name in "${KIDOBO_STAGING_CHAIN_NAME}" "${KIDOBO_CHAIN_NAME}"; do
        while true; do
            if output="$(run_with_optional_sudo "${binary}" -w 5 -D INPUT -j "${chain_name}" 2>&1)"; then
                continue
            fi
            if [[ "${output}" == *"Bad rule"* || "${output}" == *"does a matching rule exist"* ]]; then
                break
            fi
            echo "failed to remove ${binary} INPUT jump to ${chain_name}: ${output:-no diagnostic output}" >&2
            failed=1
            break
        done
    done

    for chain_name in "${KIDOBO_STAGING_CHAIN_NAME}" "${KIDOBO_CHAIN_NAME}"; do
        cleanup_allow_missing_chain "flush ${binary} chain ${chain_name}" \
            "${binary}" -w 5 -F "${chain_name}" || failed=1
        cleanup_allow_missing_chain "delete ${binary} chain ${chain_name}" \
            "${binary}" -w 5 -X "${chain_name}" || failed=1
    done
    return "${failed}"
}

cleanup_default_ipsets() {
    if ! has_cmd ipset; then
        echo "failed to confirm cleanup: ipset is unavailable" >&2
        return 1
    fi

    local failed=0
    cleanup_allow_missing_set "destroy ipset ${DEFAULT_SET_NAME}" \
        ipset destroy "${DEFAULT_SET_NAME}" || failed=1
    cleanup_allow_missing_set "destroy ipset ${DEFAULT_SET_NAME_V6}" \
        ipset destroy "${DEFAULT_SET_NAME_V6}" || failed=1
    return "${failed}"
}

cleanup_allow_missing_chain() {
    local description="$1"
    shift
    local output
    if output="$(run_with_optional_sudo "$@" 2>&1)"; then
        return 0
    fi
    if [[ "${output}" == *"No chain/target/match by that name"* ]]; then
        return 0
    fi
    echo "failed to ${description}: ${output:-no diagnostic output}" >&2
    return 1
}

cleanup_allow_missing_set() {
    local description="$1"
    shift
    local output
    if output="$(run_with_optional_sudo "$@" 2>&1)"; then
        return 0
    fi
    if [[ "${output}" == *"does not exist"* ]]; then
        return 0
    fi
    echo "failed to ${description}: ${output:-no diagnostic output}" >&2
    return 1
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
        local cleanup_failed=0
        cleanup_firewall_chain_family iptables || cleanup_failed=1
        cleanup_firewall_chain_family ip6tables || cleanup_failed=1
        cleanup_default_ipsets || cleanup_failed=1
        if [[ "${cleanup_failed}" -ne 0 ]]; then
            echo "uninstall aborted: live firewall cleanup could not be confirmed; runtime artifacts were preserved" >&2
            return 1
        fi
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

main() {
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
require_cmd mktemp
require_cmd mv

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
trap cleanup_install_temporary_files EXIT

echo "installing ${BINARY_NAME} ${VERSION} from ${REPO_SLUG}"
curl -fsSL -o "${workdir}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl -fsSL -o "${workdir}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

(
    cd "${workdir}"
    mapfile -t expected_lines < <(awk -v archive="${ARCHIVE}" '$2 == archive { print }' SHA256SUMS)
    if [[ "${#expected_lines[@]}" -eq 0 ]]; then
        echo "checksum entry not found for ${ARCHIVE}" >&2
        exit 1
    fi
    if [[ "${#expected_lines[@]}" -ne 1 ]]; then
        echo "multiple checksum entries found for ${ARCHIVE}" >&2
        exit 1
    fi
    printf '%s\n' "${expected_lines[0]}" | sha256sum -c -
)

tar -xzf "${workdir}/${ARCHIVE}" -C "${workdir}"
stage_install_file "${workdir}/kidobo-${VERSION}-linux-x86_64/${BINARY_NAME}" "${TARGET_PATH}"

expected_version="${BINARY_NAME} ${VERSION#v}"
if ! installed_version="$("${STAGED_INSTALL_PATH}" --version)"; then
    echo "downloaded ${BINARY_NAME} failed version verification" >&2
    exit 1
fi
if [[ "${installed_version}" != "${expected_version}" ]]; then
    echo "downloaded ${BINARY_NAME} reported unexpected version: ${installed_version}" >&2
    exit 1
fi

activate_staged_install "${TARGET_PATH}"

echo "installed ${BINARY_NAME} to ${TARGET_PATH}"
printf '%s\n' "${installed_version}"

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
}

if ! (return 0 2>/dev/null); then
    main "$@"
fi
