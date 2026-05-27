#!/usr/bin/env bash
set -euo pipefail

# Official Wazuh all-in-one CLI installer helper for a Linux manager host.
# Run this on a Linux VM/server, or use install_wazuh_manager_cli.ps1 to copy
# and run it over SSH from this Windows project folder.

WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
INSTALL_SCRIPT_URL="${INSTALL_SCRIPT_URL:-https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh}"
INSTALL_CAPSTONE_RULES="${INSTALL_CAPSTONE_RULES:-0}"
CAPSTONE_RULE_PATH="${CAPSTONE_RULE_PATH:-./capstone_malware_behavior_rules.xml}"
PRINT_PASSWORDS="${PRINT_PASSWORDS:-0}"
DISABLE_REPO_AFTER_INSTALL="${DISABLE_REPO_AFTER_INSTALL:-0}"

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

echo "=== Capstone Wazuh Manager CLI installer ==="
echo "Wazuh version channel: ${WAZUH_VERSION}"
echo "Install script URL: ${INSTALL_SCRIPT_URL}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "This installer must run on a Linux host." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

require_command curl
require_command tar

echo ""
echo "Downloading official Wazuh installation assistant..."
curl -fsSLo wazuh-install.sh "${INSTALL_SCRIPT_URL}"

echo ""
echo "Running official all-in-one Wazuh installation..."
run_root bash ./wazuh-install.sh -a

if [ "${INSTALL_CAPSTONE_RULES}" = "1" ]; then
  echo ""
  echo "Installing optional Capstone Wazuh rules..."
  if [ ! -f "${CAPSTONE_RULE_PATH}" ]; then
    echo "Custom rule file was not found: ${CAPSTONE_RULE_PATH}" >&2
    exit 1
  fi

  run_root install -m 0644 "${CAPSTONE_RULE_PATH}" /var/ossec/etc/rules/capstone_malware_behavior_rules.xml
  if command -v systemctl >/dev/null 2>&1; then
    run_root systemctl restart wazuh-manager
  else
    run_root service wazuh-manager restart
  fi
fi

if [ "${DISABLE_REPO_AFTER_INSTALL}" = "1" ]; then
  echo ""
  echo "Disabling Wazuh package repository after installation..."
  if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
    run_root sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
    run_root apt update
  fi
  if [ -f /etc/yum.repos.d/wazuh.repo ]; then
    run_root sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
  fi
fi

echo ""
echo "=== Service state ==="
if command -v systemctl >/dev/null 2>&1; then
  run_root systemctl --no-pager --full status wazuh-manager || true
else
  run_root service wazuh-manager status || true
fi

echo ""
echo "Alerts JSON path:"
echo "/var/ossec/logs/alerts/alerts.json"

if [ "${PRINT_PASSWORDS}" = "1" ] && [ -f wazuh-install-files.tar ]; then
  echo ""
  echo "=== Wazuh generated passwords ==="
  run_root tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
fi

echo ""
echo "Done. Next: connect the Windows agent to this manager and bridge alerts.json to the Capstone backend."
