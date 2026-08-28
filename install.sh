#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

repository="letsinferlabs/letsinfer"
version=""
base_url=""
prefix=""
launcher_dir="/usr/local/bin"
user_install=0
run_setup=1
repair_docker_access=0
docker_exec_group=""
progress_enabled=1

# BEGIN DISPLAY MANAGER

display_manager_progress_active=0
display_manager_interactive=0
display_manager_brand_mark=">"
display_manager_success_mark="+"
display_manager_failure_mark="x"
display_manager_badge_text=">  LET'S INFER"
display_manager_blue=""
display_manager_green=""
display_manager_red=""
display_manager_dim=""
display_manager_reset=""

# Configures presentation from explicit terminal, locale, color, and progress facts.
display_manager_configure() {
    display_manager_requested_interactive=$1
    display_manager_locale=$2
    display_manager_color_enabled=$3
    display_manager_progress_enabled=$4
    case "$display_manager_requested_interactive/$display_manager_color_enabled/$display_manager_progress_enabled" in
        0/0/0|0/0/1|0/1/0|0/1/1|1/0/0|1/0/1|1/1/0|1/1/1) ;;
        *) return 1 ;;
    esac
    display_manager_interactive=$display_manager_requested_interactive
    if [ "$display_manager_interactive" -eq 1 ] \
        && [ "$display_manager_progress_enabled" -eq 1 ]; then
        display_manager_progress_active=1
    fi
    case "$display_manager_locale" in
        *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*)
            display_manager_brand_mark="ϟ"
            display_manager_success_mark="✓"
            display_manager_failure_mark="✗"
            ;;
    esac
    if [ "$display_manager_interactive" -eq 1 ] \
        && [ "$display_manager_color_enabled" -eq 1 ]; then
        display_manager_reset=$(printf '\033[0m')
        display_manager_blue=$(printf '\033[1;38;2;0;156;223m')
        display_manager_green=$(printf '\033[1;38;2;97;187;70m')
        display_manager_red=$(printf '\033[1;38;2;226;56;56m')
        display_manager_dim=$(printf '\033[2m')
        display_manager_badge_text=$(printf \
            '\033[1;38;2;30;30;30;48;2;247;247;247m %s  LET\047S INFER \033[0m' \
            "$display_manager_brand_mark")
    else
        display_manager_badge_text="$display_manager_brand_mark  LET'S INFER"
    fi
}

# Clears the active progress row before another presentation replaces it.
display_manager_clear_progress() {
    if [ "$display_manager_progress_active" -eq 1 ]; then
        printf '\r\033[2K' >&2
    fi
}

# Presents one stable installation stage on an interactive terminal.
display_manager_present_progress() {
    display_manager_percent=$1
    display_manager_message=$2
    if [ "$display_manager_progress_active" -eq 1 ]; then
        printf '\r\033[2K%s  %sINSTALL%s  %s%3s%%%s  %s' \
            "$display_manager_badge_text" "$display_manager_blue" \
            "$display_manager_reset" "$display_manager_blue" \
            "$display_manager_percent" "$display_manager_reset" \
            "$display_manager_message" >&2
    fi
}

# Completes the active progress row without presenting product state.
display_manager_finish_progress() {
    if [ "$display_manager_progress_active" -eq 1 ]; then
        display_manager_present_progress 100 "Complete"
        printf '\n' >&2
        display_manager_progress_active=0
    fi
}

# Presents one installation failure through the configured language and marks.
display_manager_present_failure() {
    display_manager_clear_progress
    display_manager_progress_active=0
    if [ "$display_manager_interactive" -eq 1 ]; then
        printf '%s  %sINSTALL%s\n\n%s%s  Installation failed%s\n   %s\n' \
            "$display_manager_badge_text" "$display_manager_red" \
            "$display_manager_reset" "$display_manager_red" \
            "$display_manager_failure_mark" "$display_manager_reset" "$*" >&2
    else
        printf 'letsinfer install: %s\n' "$*" >&2
    fi
}

# Presents a required login refresh and ends the interactive lifecycle.
display_manager_present_login_refresh() {
    display_manager_clear_progress
    display_manager_progress_active=0
    if [ "$display_manager_interactive" -eq 1 ]; then
        printf '%s  %sINSTALL%s\n\n%s!  Login refresh required%s\n   %s\n' \
            "$display_manager_badge_text" "$display_manager_blue" \
            "$display_manager_reset" "$display_manager_blue" \
            "$display_manager_reset" "$*" >&2
    else
        printf 'letsinfer install: %s\n' "$*" >&2
    fi
}

# Presents one installation notice without exposing display mechanics to callers.
display_manager_present_notice() {
    display_manager_clear_progress
    printf 'letsinfer install: %s\n' "$*" >&2
}

# Requests explicit approval through the controlling terminal when available.
display_manager_request_approval() {
    display_manager_approval_description=$1
    if ! ( : </dev/tty && : >/dev/tty ) 2>/dev/null; then
        return 1
    fi
    printf '%s\nContinue? [y/N] ' \
        "$display_manager_approval_description" >/dev/tty
    display_manager_approval_answer=""
    IFS= read -r display_manager_approval_answer </dev/tty || true
    case "$display_manager_approval_answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# Presents the bounded diagnostic tail from one failed installation phase.
display_manager_present_log_tail() {
    display_manager_clear_progress
    tail -n "$2" "$1" >&2
}

# Presents one verified installation summary without transforming its fields.
display_manager_present_summary() {
    sed -n '1,$p' "$1" >&2
}

# Presents the one user-local launcher path action required after installation.
display_manager_present_path_notice() {
    printf 'Open a new shell after adding %s/bin to PATH.\n' "$1" >&2
}

# Presents the completed Core installation and canonical platform.
display_manager_present_completion() {
    display_manager_version=$1
    display_manager_completion=$2
    display_manager_operating_system=$3
    display_manager_architecture=$4
    if [ "$display_manager_interactive" -eq 1 ]; then
        printf '%s  %s%s%s  Let\047s Infer %s %s\n' \
            "$display_manager_badge_text" "$display_manager_green" \
            "$display_manager_success_mark" "$display_manager_reset" \
            "$display_manager_version" "$display_manager_completion" >&2
        printf '   %s%s/%s%s\n' "$display_manager_dim" \
            "$display_manager_operating_system" "$display_manager_architecture" \
            "$display_manager_reset" >&2
    else
        printf 'Let\047s Infer %s %s for %s/%s.\n' \
            "$display_manager_version" "$display_manager_completion" \
            "$display_manager_operating_system" \
            "$display_manager_architecture" >&2
    fi
}

# END DISPLAY MANAGER

# Prints the supported public bootstrap arguments and installation boundary.
usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--prefix PATH] [--user] [--no-setup] [--no-progress]
                  [--repair-docker-access]

Install and initialize the latest published Let's Infer core release. Immutable
core files live under $LETSINFER_HOME/core. The default exposes the command in
/usr/local/bin; --user exposes it from ~/.local/bin without administrator access.
On Linux, --repair-docker-access explicitly approves adding the operator to the
Docker socket group or restarting a stale user service manager when required.
EOF
}

# Ends installation through the single configured display failure boundary.
fail() {
    display_manager_present_failure "$*"
    exit 1
}

# Returns the first macOS Python satisfying the complete Core runtime contract.
select_macos_python() {
    if [ -n "${LETSINFER_PYTHON:-}" ]; then
        set -- "$LETSINFER_PYTHON"
    else
        set -- \
            python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3 \
            /opt/homebrew/opt/python@3.14/bin/python3.14 \
            /opt/homebrew/opt/python@3.13/bin/python3.13 \
            /opt/homebrew/opt/python@3.12/bin/python3.12 \
            /opt/homebrew/opt/python@3.11/bin/python3.11 \
            /opt/homebrew/opt/python@3.10/bin/python3.10 \
            /opt/homebrew/opt/python@3.9/bin/python3.9 \
            /usr/local/opt/python@3.14/bin/python3.14 \
            /usr/local/opt/python@3.13/bin/python3.13 \
            /usr/local/opt/python@3.12/bin/python3.12 \
            /usr/local/opt/python@3.11/bin/python3.11 \
            /usr/local/opt/python@3.10/bin/python3.10 \
            /usr/local/opt/python@3.9/bin/python3.9 \
            /opt/local/bin/python3.14 \
            /opt/local/bin/python3.13 \
            /opt/local/bin/python3.12 \
            /opt/local/bin/python3.11 \
            /opt/local/bin/python3.10 \
            /opt/local/bin/python3.9
    fi
    for candidate do
        case "$candidate" in
            */*) python_path=$candidate ;;
            *) python_path=$(command -v "$candidate" 2>/dev/null || true) ;;
        esac
        [ -n "$python_path" ] && [ -x "$python_path" ] || continue
        resolved=$(
            "$python_path" - <<'PY' 2>/dev/null
import hashlib
import http.server
import pathlib
import plistlib
import sqlite3
import ssl
import sys
import urllib.request

if sys.version_info < (3, 9) or not getattr(ssl, "HAS_TLSv1_3", False):
    raise SystemExit(1)
hashlib.sha256(b"letsinfer").digest()
sqlite3.connect(":memory:").close()
plistlib.dumps({"letsinfer": True})
path = pathlib.Path(sys.executable).absolute()
if not path.is_file():
    raise SystemExit(1)
print(path)
PY
        ) || continue
        printf '%s\n' "$resolved"
        return 0
    done
    return 1
}

# Presents a required login refresh and exits with its stable status.
pause_for_login_refresh() {
    display_manager_present_login_refresh "$*"
    exit 2
}

# Obtains explicit approval before granting Docker socket access.
approve_docker_repair() {
    repair_description=$1
    if [ "$repair_docker_access" -eq 1 ]; then
        return 0
    fi
    if display_manager_request_approval "$repair_description"; then
        repair_docker_access=1
        return 0
    fi
    if ( : </dev/tty && : >/dev/tty ) 2>/dev/null; then
        fail "Docker access repair was not approved"
    fi
    fail "Docker access repair requires approval; rerun with --repair-docker-access"
}

# Returns whether one exact group identifier occurs in a normalized group list.
gid_list_contains() {
    wanted_gid=$1
    gid_list=$2
    case " $gid_list " in
        *" $wanted_gid "*) return 0 ;;
        *) return 1 ;;
    esac
}

# Activates newly granted Docker group access for this installation process.
activate_docker_group_for_install() {
    operator=$1
    socket_group=$2
    command -v sg >/dev/null 2>&1 \
        || pause_for_login_refresh \
            "$operator belongs to $socket_group, but this login has stale groups and sg is unavailable. Close every session for this account, sign in again, and rerun install.sh."
    if ! sg "$socket_group" -c 'docker info >/dev/null 2>&1'; then
        pause_for_login_refresh \
            "$operator belongs to $socket_group, but a refreshed group process cannot reach Docker. Close every session for this account, sign in again, and rerun install.sh."
    fi
    docker_exec_group=$socket_group
    display_manager_present_notice \
        "using refreshed $socket_group group access for this installation."
}

# Returns the validated distribution identity from one Linux release document.
linux_distribution_id() {
    os_release_path=$1
    [ -f "$os_release_path" ] || return 1
    "$python_command" - "$os_release_path" <<'PY'
import pathlib
import re
import shlex
import sys

try:
    document = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
except (OSError, UnicodeError):
    raise SystemExit(1)
if len(document) > 64 * 1024:
    raise SystemExit(1)
distribution = None
for line in document.splitlines():
    key, separator, raw_value = line.partition("=")
    if separator != "=" or key != "ID":
        continue
    try:
        values = shlex.split(raw_value, comments=True, posix=True)
    except ValueError:
        raise SystemExit(1)
    if len(values) != 1 or re.fullmatch(r"[a-z0-9._-]+", values[0]) is None:
        raise SystemExit(1)
    distribution = values[0]
    break
if distribution is None:
    raise SystemExit(1)
print(distribution)
PY
}

# Installs and verifies Docker through the selected Linux package provider.
install_linux_docker() {
    os_release_path=$1
    command -v sudo >/dev/null 2>&1 \
        || fail "Docker is not installed and sudo is required to install it"
    [ -f "$os_release_path" ] \
        || fail "Linux distribution metadata is unavailable: $os_release_path"
    distribution=$(linux_distribution_id "$os_release_path") \
        || fail "Linux distribution metadata is invalid: $os_release_path"

    display_manager_present_notice \
        "Docker is not installed; installing it with sudo for $distribution."
    case "$distribution" in
        ubuntu|debian)
            command -v apt-get >/dev/null 2>&1 \
                || fail "$distribution Docker installation requires apt-get"
            sudo apt-get update \
                || fail "apt could not refresh package metadata for Docker"
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io \
                || fail "apt could not install Docker"
            ;;
        fedora)
            command -v dnf >/dev/null 2>&1 \
                || fail "Fedora Docker installation requires dnf"
            sudo dnf install -y moby-engine \
                || fail "dnf could not install Docker"
            ;;
        opensuse-leap|opensuse-tumbleweed|sles)
            command -v zypper >/dev/null 2>&1 \
                || fail "$distribution Docker installation requires zypper"
            sudo zypper --non-interactive install docker \
                || fail "zypper could not install Docker"
            ;;
        arch|manjaro)
            command -v pacman >/dev/null 2>&1 \
                || fail "$distribution Docker installation requires pacman"
            sudo pacman --sync --needed --noconfirm docker \
                || fail "pacman could not install Docker"
            ;;
        *)
            fail "automatic Docker installation is unsupported on Linux distribution: $distribution"
            ;;
    esac

    # POSIX shells may cache a prior failed Docker lookup. Refresh command
    # discovery before validating the package that was just installed.
    hash -r 2>/dev/null || :
    command -v docker >/dev/null 2>&1 \
        || fail "the Docker package installed, but its CLI remains unavailable"
    docker --version >/dev/null 2>&1 \
        || fail "the Docker package installed, but its CLI is unusable"
    sudo systemctl enable --now docker.service \
        || fail "Docker installed, but docker.service could not be enabled and started"
    sudo docker info >/dev/null 2>&1 \
        || fail "Docker installed, but its daemon did not become healthy"
}

# Verifies an existing Docker CLI or installs it through the Linux provider.
ensure_linux_docker() {
    os_release_path=${1:-/etc/os-release}
    if command -v docker >/dev/null 2>&1; then
        docker --version >/dev/null 2>&1 \
            || fail "Docker is installed, but its CLI is unusable"
        return 0
    fi
    install_linux_docker "$os_release_path"
}

# Applies Docker readiness only to platforms that require it.
ensure_platform_docker() {
    target_platform=$1
    os_release_path=${2:-/etc/os-release}
    [ "$target_platform" = "linux" ] || return 0
    ensure_linux_docker "$os_release_path"
}

# Installs and verifies local discovery through the selected Linux provider.
install_linux_mdns() {
    os_release_path=$1
    command -v sudo >/dev/null 2>&1 \
        || fail "Avahi is unavailable and sudo is required to install it"
    distribution=$(linux_distribution_id "$os_release_path") \
        || fail "Linux distribution metadata is invalid: $os_release_path"
    display_manager_present_notice \
        "installing local discovery support with sudo for $distribution."
    case "$distribution" in
        ubuntu|debian)
            command -v apt-get >/dev/null 2>&1 \
                || fail "$distribution local discovery installation requires apt-get"
            sudo apt-get update \
                || fail "apt could not refresh package metadata for local discovery"
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                avahi-daemon avahi-utils \
                || fail "apt could not install local discovery support"
            ;;
        fedora)
            command -v dnf >/dev/null 2>&1 \
                || fail "Fedora local discovery installation requires dnf"
            sudo dnf install -y avahi avahi-tools \
                || fail "dnf could not install local discovery support"
            ;;
        opensuse-leap|opensuse-tumbleweed|sles)
            command -v zypper >/dev/null 2>&1 \
                || fail "$distribution local discovery installation requires zypper"
            sudo zypper --non-interactive install avahi avahi-utils \
                || fail "zypper could not install local discovery support"
            ;;
        arch|manjaro)
            command -v pacman >/dev/null 2>&1 \
                || fail "$distribution local discovery installation requires pacman"
            sudo pacman --sync --needed --noconfirm avahi \
                || fail "pacman could not install local discovery support"
            ;;
        *)
            fail "automatic local discovery installation is unsupported on Linux distribution: $distribution"
            ;;
    esac
    hash -r 2>/dev/null || :
}

# Verifies existing local discovery or installs it through the Linux provider.
ensure_linux_mdns() {
    os_release_path=${1:-/etc/os-release}
    if ! command -v avahi-publish-service >/dev/null 2>&1 \
        || ! command -v avahi-browse >/dev/null 2>&1; then
        install_linux_mdns "$os_release_path"
    fi
    command -v avahi-publish-service >/dev/null 2>&1 \
        || fail "local discovery publisher remains unavailable after installation"
    command -v avahi-browse >/dev/null 2>&1 \
        || fail "local node discovery remains unavailable after installation"
    if ! systemctl is-active --quiet avahi-daemon.service; then
        command -v sudo >/dev/null 2>&1 \
            || fail "sudo is required to start local discovery"
        sudo systemctl enable --now avahi-daemon.service \
            || fail "local discovery installed, but avahi-daemon.service could not start"
    fi
    systemctl is-active --quiet avahi-daemon.service \
        || fail "local discovery daemon is unavailable"
}

# Applies local-discovery readiness only to platforms that require it.
ensure_platform_mdns() {
    target_platform=$1
    os_release_path=${2:-/etc/os-release}
    [ "$target_platform" = "linux" ] || return 0
    ensure_linux_mdns "$os_release_path"
}

# Verifies or explicitly repairs operator access to the Linux Docker daemon.
preflight_linux_docker() {
    operator=$1
    if docker info >/dev/null 2>&1; then
        return 0
    fi

    command -v sudo >/dev/null 2>&1 \
        || fail "Docker is installed, but the operator cannot reach its daemon and sudo is unavailable for diagnosis"
    if ! sudo docker info >/dev/null 2>&1; then
        fail "the Docker daemon is unavailable or unhealthy; start it and verify that sudo docker info succeeds"
    fi

    docker_socket=/var/run/docker.sock
    socket_group_record=$(stat -Lc '%g:%G' "$docker_socket" 2>/dev/null || true)
    case "$socket_group_record" in
        *:*) ;;
        *) fail "the Docker daemon is healthy, but $docker_socket is unavailable" ;;
    esac
    socket_gid=${socket_group_record%%:*}
    socket_group=${socket_group_record#*:}
    case "$socket_gid" in
        ''|*[!0-9]*) fail "the Docker socket group identity is invalid" ;;
    esac
    case "$socket_group" in
        ''|UNKNOWN|root|*[!A-Za-z0-9_.-]*)
            fail "the Docker socket group cannot be enrolled safely: $socket_group"
            ;;
    esac

    active_gids=$(id -G)
    if gid_list_contains "$socket_gid" "$active_gids"; then
        fail "the operator already has the Docker socket group, but docker info still fails; inspect the Docker client configuration"
    fi
    account_gids=$(id -G "$operator")
    if gid_list_contains "$socket_gid" "$account_gids"; then
        activate_docker_group_for_install "$operator" "$socket_group"
        return 0
    fi

    command -v usermod >/dev/null 2>&1 \
        || fail "Docker access requires adding $operator to $socket_group, but usermod is unavailable"
    approve_docker_repair \
        "Docker is healthy, but $operator cannot access $docker_socket. Add $operator to $socket_group? Membership grants root-equivalent access."
    sudo usermod -aG "$socket_group" "$operator"
    account_gids=$(id -G "$operator")
    gid_list_contains "$socket_gid" "$account_gids" \
        || fail "Docker group enrollment did not take effect"
    activate_docker_group_for_install "$operator" "$socket_group"
}

# Returns whether a transient user service can reach the Docker daemon.
docker_user_service_access() {
    unit_suffix=$1
    systemd-run --user --quiet --wait --collect \
        --unit="letsinfer-docker-preflight-$$-$unit_suffix" \
        docker info >/dev/null 2>&1
}

# Verifies persistent user services inherit working Docker access.
preflight_linux_docker_service() {
    if docker_user_service_access initial; then
        return 0
    fi
    approve_docker_repair \
        "Docker works in this shell, but the running user service manager has stale groups. Restart it now? This briefly restarts this account's user services."
    command -v sudo >/dev/null 2>&1 \
        || fail "sudo is required to restart the stale user service manager"
    sudo systemctl restart "user@$(id -u).service"
    attempt=0
    while [ "$attempt" -lt 10 ]; do
        attempt=$((attempt + 1))
        if docker_user_service_access "$attempt"; then
            return 0
        fi
        sleep 1
    done
    fail "Docker works in this shell, but user services still cannot reach it; reboot once and rerun install.sh"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || fail "--version requires a value"
            version=$2
            shift 2
            ;;
        --prefix)
            [ "$#" -ge 2 ] || fail "--prefix requires a value"
            prefix=$2
            user_install=1
            shift 2
            ;;
        --user)
            [ -z "$prefix" ] || fail "--user and --prefix cannot be combined"
            prefix="$HOME/.local"
            user_install=1
            shift
            ;;
        --no-setup)
            run_setup=0
            shift
            ;;
        --no-progress)
            progress_enabled=0
            shift
            ;;
        --repair-docker-access)
            repair_docker_access=1
            shift
            ;;
        --base-url)
            [ "$#" -ge 2 ] || fail "--base-url requires a value"
            base_url=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[ "$(id -u)" -ne 0 ] || fail "run this installer as the user who will operate Let's Infer, not root"
[ -n "$HOME" ] || fail "HOME is unavailable"
allow_insecure=$(printenv LETSINFER_ALLOW_INSECURE_RELEASE_URL 2>/dev/null || true)
signers_override=$(printenv LETSINFER_RELEASE_ALLOWED_SIGNERS_PATH 2>/dev/null || true)
current_path=$(printenv PATH 2>/dev/null || true)
if [ -n "${LETSINFER_HOME:-}" ]; then
    letsinfer_home=$LETSINFER_HOME
else
    letsinfer_home="$HOME/.local/share/letsinfer"
    LETSINFER_HOME_DEFAULTED=1
    export LETSINFER_HOME_DEFAULTED
fi
case "$letsinfer_home" in
    /*) ;;
    *) fail "LETSINFER_HOME must be an absolute path" ;;
esac
LETSINFER_HOME=$letsinfer_home
export LETSINFER_HOME
installer_interactive_output=0
case "${TERM:-}" in
    ""|dumb) ;;
    *)
        if [ -t 2 ]; then
            installer_interactive_output=1
        fi
        ;;
esac
installer_color_output=0
if [ -z "${NO_COLOR+x}" ]; then
    installer_color_output=1
fi
display_manager_configure \
    "$installer_interactive_output" \
    "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" \
    "$installer_color_output" \
    "$progress_enabled" \
    || fail "display manager configuration is invalid"

case "$(uname -s)" in
    Linux) platform_os="linux" ;;
    Darwin) platform_os="macos" ;;
    *) fail "supported operating systems are Linux and macOS" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) platform_arch="x86_64" ;;
    arm64|aarch64) platform_arch="arm64" ;;
    *) fail "supported architectures are x86_64 and arm64" ;;
esac
archive_name="letsinfer-$platform_os-$platform_arch.tar.gz"

for command_name in curl ssh-keygen tar mktemp; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command is unavailable: $command_name"
done
python_command=python3
if [ "$platform_os" = "macos" ]; then
    python_command=$(select_macos_python) \
        || fail "macOS requires a working Python 3.9 or newer with TLS 1.3 support"
else
    command -v python3 >/dev/null 2>&1 \
        || fail "required command is unavailable: python3"
fi
export LETSINFER_PYTHON=$python_command
if [ "$user_install" -eq 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "sudo is required for the default system installation"
    sudo -v
fi

if [ "$run_setup" -eq 1 ] && [ "$platform_os" = "linux" ]; then
    for setup_command in loginctl systemctl systemd-run stat; do
        command -v "$setup_command" >/dev/null 2>&1 \
            || fail "automatic Linux setup requires: $setup_command"
    done
    ensure_platform_docker "$platform_os"
    ensure_platform_mdns "$platform_os"
    operator=$(id -un)
    preflight_linux_docker "$operator"
fi

if [ -n "$version" ]; then
    "$python_command" - "$version" <<'PY' || fail "version is not a release or release candidate"
import re
import sys

if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", sys.argv[1]) is None:
    raise SystemExit(1)
PY
fi

umask 077
[ ! -L "$LETSINFER_HOME" ] || fail "LETSINFER_HOME cannot be a symlink"
mkdir -p "$LETSINFER_HOME"
chmod 0700 "$LETSINFER_HOME"
temporary=$(mktemp -d "/tmp/letsinfer-install.XXXXXXXX")
# Removes the exact temporary installation root owned by this invocation.
cleanup() {
    display_manager_clear_progress
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

# Returns whether native OpenSSL development headers can be compiled.
openssl_development_ready() {
    command -v cc >/dev/null 2>&1 || return 1
    printf '#include <openssl/ssl.h>\n' \
        | cc -E - >/dev/null 2>&1
}

# Installs and verifies build requirements needed by automatic Core setup.
ensure_setup_dependencies() {
    [ "$run_setup" -eq 1 ] || return 0
    if [ "$platform_os" = "linux" ]; then
        ready=1
        for setup_command in cmake ctest cc openssl; do
            command -v "$setup_command" >/dev/null 2>&1 || ready=0
        done
        openssl_development_ready || ready=0
        [ "$ready" -eq 0 ] || return 0
        command -v sudo >/dev/null 2>&1 \
            || fail "sudo is required to install system build requirements"
        display_manager_present_progress 10 "Installing system requirements"
        dependency_log="$temporary/dependencies.log"
        if command -v apt-get >/dev/null 2>&1; then
            if ! {
                sudo apt-get update -qq &&
                sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                    build-essential cmake openssl libssl-dev
            } >"$dependency_log" 2>&1; then
                display_manager_present_log_tail "$dependency_log" 40
                fail "apt could not install system build requirements"
            fi
        elif command -v dnf >/dev/null 2>&1; then
            if ! sudo dnf install -y gcc gcc-c++ make cmake openssl openssl-devel \
                >"$dependency_log" 2>&1; then
                display_manager_present_log_tail "$dependency_log" 40
                fail "dnf could not install system build requirements"
            fi
        elif command -v zypper >/dev/null 2>&1; then
            if ! sudo zypper --non-interactive install \
                gcc gcc-c++ make cmake openssl libopenssl-devel \
                >"$dependency_log" 2>&1; then
                display_manager_present_log_tail "$dependency_log" 40
                fail "zypper could not install system build requirements"
            fi
        elif command -v pacman >/dev/null 2>&1; then
            if ! sudo pacman --sync --needed --noconfirm \
                base-devel cmake openssl >"$dependency_log" 2>&1; then
                display_manager_present_log_tail "$dependency_log" 40
                fail "pacman could not install system build requirements"
            fi
        else
            fail "install a C compiler, CMake, and OpenSSL development headers"
        fi
        for setup_command in cmake ctest cc openssl; do
            command -v "$setup_command" >/dev/null 2>&1 \
                || fail "system requirement remains unavailable: $setup_command"
        done
        openssl_development_ready \
            || fail "OpenSSL development headers remain unavailable"
    fi
}

display_manager_present_progress 5 "Resolving release"
ensure_setup_dependencies

checksums="$temporary/SHA256SUMS"
signature="$temporary/SHA256SUMS.sig"
archive="$temporary/$archive_name"
allowed_signers="$temporary/release-allowed-signers"

curl_protocols="=https"
if [ "$allow_insecure" = "1" ]; then
    curl_protocols="=https,http,file"
fi

# Downloads one release input after enforcing its approved URL scheme.
download() {
    source_url=$1
    output_path=$2
    case "$source_url" in
        https://*) ;;
        http://*|file://*)
            [ "$allow_insecure" = "1" ] \
                || fail "release URL must use HTTPS"
            ;;
        *) fail "release URL is invalid" ;;
    esac
    curl --fail --location --silent --show-error \
        --proto "$curl_protocols" --tlsv1.2 \
        --output "$output_path" "$source_url"
}

if [ -n "$base_url" ]; then
    release_base=$base_url
    download "$release_base/SHA256SUMS" "$checksums"
elif [ -n "$version" ]; then
    release_base="https://github.com/$repository/releases/download/v$version"
    download "$release_base/SHA256SUMS" "$checksums"
else
    metadata="$temporary/releases.json"
    download "https://api.github.com/repos/$repository/releases?per_page=30" "$metadata"
    version=$("$python_command" - "$metadata" <<'PY'
import json
import pathlib
import re
import sys

try:
    value = pathlib.Path(sys.argv[1]).read_bytes()
    if len(value) > 1024 * 1024:
        raise ValueError
    releases = json.loads(value)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(releases, list):
    raise SystemExit(1)
pattern = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-rc\.([0-9]+))?")
candidates = []
for release in releases:
    if not isinstance(release, dict) or release.get("draft") is not False:
        continue
    tag = release.get("tag_name")
    match = pattern.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        continue
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    rc = match.group(4)
    key = (major, minor, patch, 1 if rc is None else 0, int(rc or 0))
    candidates.append((key, tag[1:]))
if not candidates:
    raise SystemExit(1)
print(max(candidates)[1])
PY
    ) || fail "latest published release metadata is invalid"
    release_base="https://github.com/$repository/releases/download/v$version"
    download "$release_base/SHA256SUMS" "$checksums"
fi

download "$release_base/SHA256SUMS.sig" "$signature"
download "$release_base/$archive_name" "$archive"
display_manager_present_progress 35 "Verifying signed release"

if [ -n "$signers_override" ]; then
    [ -f "$signers_override" ] \
        || fail "release allowed-signers override is unavailable"
    cp "$signers_override" "$allowed_signers"
else
    cat >"$allowed_signers" <<'LETSINFER_RELEASE_ALLOWED_SIGNERS'
letsinfer-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPl4ZwPrMfdYYPxhqcMGtpOlM0EoFCaHlMfjme8xV23
LETSINFER_RELEASE_ALLOWED_SIGNERS
fi

ssh-keygen -Y verify -f "$allowed_signers" -I letsinfer-release \
    -n letsinfer-release -s "$signature" <"$checksums" >/dev/null 2>&1 \
    || fail "release checksum signature is invalid"

"$python_command" - "$checksums" "$archive_name" "$archive" <<'PY' \
    || fail "release archive checksum is invalid"
import hashlib
import pathlib
import re
import sys

document = pathlib.Path(sys.argv[1]).read_bytes()
name = sys.argv[2]
archive = pathlib.Path(sys.argv[3])
if len(document) > 1024 * 1024:
    raise SystemExit(1)
records = {}
for line in document.splitlines():
    match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
    if match is None:
        raise SystemExit(1)
    item = match.group(2).decode("ascii")
    if item in records:
        raise SystemExit(1)
    records[item] = match.group(1).decode("ascii")
expected = records.get(name)
if expected is None:
    raise SystemExit(1)
digest = hashlib.sha256()
with archive.open("rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != expected:
    raise SystemExit(1)
PY

display_manager_present_progress 55 "Verifying source archive"

unpacked="$temporary/unpacked"
mkdir "$unpacked"
tar -xzf "$archive" -C "$unpacked"
[ -d "$unpacked/letsinfer" ] || fail "release archive root is missing"
(cd "$unpacked/letsinfer" && "$python_command" -m tools.source_archive verify "$archive" >/dev/null) \
    || fail "release source manifest verification failed"
if [ -z "$version" ]; then
    version=$(
        cd "$unpacked/letsinfer"
        "$python_command" -c 'from core import PRODUCT_VERSION; print(PRODUCT_VERSION)'
    ) || fail "release version is unreadable"
fi

if [ "$run_setup" -eq 1 ] && [ "$platform_os" = "linux" ] \
    && [ "$user_install" -eq 0 ]; then
    display_manager_present_progress 65 "Preparing platform networking"
    network_log="$temporary/platform-network.log"
    if ! (cd "$unpacked/letsinfer" && \
        "$python_command" -m core.platform.network apply-if-detected) \
        >"$network_log" 2>&1; then
        display_manager_present_log_tail "$network_log" 40
        fail "platform network setup failed"
    fi
fi

display_manager_present_progress 70 "Installing core"

if [ "$run_setup" -eq 1 ]; then
    if [ "$platform_os" = "linux" ]; then
        linger=$(loginctl show-user "$operator" --property Linger --value 2>/dev/null || true)
        if [ "$linger" != "yes" ]; then
            command -v sudo >/dev/null 2>&1 \
                || fail "sudo is required once to enable persistent user services"
            sudo loginctl enable-linger "$operator"
            linger=$(loginctl show-user "$operator" --property Linger --value 2>/dev/null || true)
            [ "$linger" = "yes" ] \
                || fail "persistent user services could not be enabled"
        fi
        preflight_linux_docker_service
    else
        launchctl print "gui/$(id -u)" >/dev/null 2>&1 \
            || fail "automatic setup requires an active macOS login session"
    fi
fi

umask 022
if [ "$user_install" -eq 1 ]; then
    if [ "$platform_os" = "macos" ]; then
        "$unpacked/letsinfer/bin/li_installer_core" \
            --home "$LETSINFER_HOME" --launcher-root "$prefix/bin" \
            --python "$python_command" >/dev/null
    else
        "$unpacked/letsinfer/bin/li_installer_core" \
            --home "$LETSINFER_HOME" --launcher-root "$prefix/bin" >/dev/null
    fi
    command_path="$prefix/bin/letsinfer"
else
    if [ "$platform_os" = "macos" ]; then
        "$unpacked/letsinfer/bin/li_installer_core" \
            --home "$LETSINFER_HOME" --python "$python_command" >/dev/null
    else
        "$unpacked/letsinfer/bin/li_installer_core" \
            --home "$LETSINFER_HOME" >/dev/null
    fi
    sudo install -d -m 0755 "$launcher_dir"
    for launcher_name in letsinfer letsinfer-recovery; do
        launcher="$launcher_dir/$launcher_name"
        if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
            fail "refusing to replace a non-symlink launcher: $launcher"
        fi
        temporary_launcher="$launcher.letsinfer.$$"
        sudo rm -f -- "$temporary_launcher"
        sudo ln -s "$LETSINFER_HOME/core/current/bin/$launcher_name" "$temporary_launcher"
        sudo mv -f -- "$temporary_launcher" "$launcher"
    done
    command_path="$launcher_dir/letsinfer"
fi
umask 077

if [ "$run_setup" -eq 1 ]; then
    setup_json="$temporary/setup.json"
    setup_log="$temporary/setup.stderr"
    setup_summary="$temporary/setup.summary"
    display_manager_present_progress 80 "Initializing services"
    if [ -n "$docker_exec_group" ]; then
        LETSINFER_SETUP_COMMAND=$command_path
        export LETSINFER_SETUP_COMMAND
        if ! sg "$docker_exec_group" \
            -c 'exec "$LETSINFER_SETUP_COMMAND" core-setup --json' \
            >"$setup_json" 2>"$setup_log"; then
            setup_failed=1
        else
            setup_failed=0
        fi
        unset LETSINFER_SETUP_COMMAND
    elif ! "$command_path" core-setup --json >"$setup_json" 2>"$setup_log"; then
        setup_failed=1
    else
        setup_failed=0
    fi
    if [ "$setup_failed" -ne 0 ]; then
        display_manager_clear_progress
        display_manager_progress_active=0
        if [ -s "$setup_log" ]; then
            display_manager_present_log_tail "$setup_log" 80
        fi
        fail "site initialization failed"
    fi
    if ! "$python_command" - "$setup_json" >"$setup_summary" <<'PY'
import json
import pathlib
import sys

try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, dict):
    raise SystemExit(1)

def safe_field(name, *, required=False):
    item = value.get(name)
    if item is None and not required:
        return None
    if not isinstance(item, str) or not item.strip():
        raise SystemExit(1)
    if any(ord(character) < 32 or ord(character) == 127 for character in item):
        raise SystemExit(1)
    return item

node = safe_field("display_name", required=True)
endpoint = safe_field("inference_endpoint")
key_file = safe_field("api_key_file")
print(f"   Node      {node}")
if endpoint:
    print(f"   API       {endpoint}")
if key_file:
    print(f"   API key   {key_file}")
PY
    then
        fail "site initialization result is invalid"
    fi
fi

display_manager_finish_progress

if [ "$run_setup" -eq 1 ]; then
    completion="installed and initialized"
else
    completion="installed"
fi
display_manager_present_completion \
    "$version" "$completion" "$platform_os" "$platform_arch"
if [ "$run_setup" -eq 1 ]; then
    display_manager_present_summary "$setup_summary"
fi
if [ "$user_install" -eq 1 ]; then
    case ":$current_path:" in
        *":$prefix/bin:"*) ;;
        *) display_manager_present_path_notice "$prefix" ;;
    esac
fi
