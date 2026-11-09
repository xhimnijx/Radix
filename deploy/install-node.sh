#!/usr/bin/env bash
# Install the Radix testnet node on Ubuntu as a systemd service.
#
# Usage, from the repository root:
#   sudo ./deploy/install-node.sh
#
# What it does not do, deliberately: open a firewall port, install WireGuard, or
# configure DNS. Those are covered in DEPLOY.md, and the node has no authentication,
# so exposing it is a decision someone should make on purpose rather than inherit
# from an installer.

set -euo pipefail

SERVICE_USER="radix"
INSTALL_DIR="/opt/radix"
DATA_DIR="/var/lib/radix"
UNIT_NAME="radix-node.service"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "run this with sudo"
[[ -f pyproject.toml && -d radix_testnet ]] || fail "run this from the repository root"
command -v systemctl >/dev/null || fail "systemd is required"

say "Installing packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-venv python3-pip rsync >/dev/null

PYTHON_VERSION=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
say "Python $PYTHON_VERSION detected"
python3 - <<'PY' || fail "Python 3.12 or newer is required (check pyproject.toml)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY

say "Creating the service user"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

say "Copying the application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
    --exclude '.git' --exclude 'build' --exclude 'dist' --exclude '*.apk' \
    --exclude 'proof_rust/target' --exclude 'android' --exclude '__pycache__' \
    ./ "$INSTALL_DIR"/

say "Creating the virtual environment"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -e "$INSTALL_DIR"

say "Preparing $DATA_DIR"
mkdir -p "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$INSTALL_DIR"
chmod 700 "$DATA_DIR"

if [[ -f "$DATA_DIR/wallet.mnemonic" ]]; then
    say "An existing wallet was found; keeping it"
else
    say "No wallet yet - it will be created on first start"
fi

say "Installing the systemd unit"
install -m 0644 deploy/radix-node.service "/etc/systemd/system/$UNIT_NAME"
systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null
systemctl restart "$UNIT_NAME"

sleep 3
if ! systemctl is-active --quiet "$UNIT_NAME"; then
    journalctl -u "$UNIT_NAME" -n 30 --no-pager || true
    fail "the service did not start"
fi

say "Node is running"
if [[ -f "$DATA_DIR/wallet.mnemonic" ]]; then
    # Only show the phrase on the run that created it; a phrase printed twice is a
    # phrase printed once too often.
    if grep -q "NEW WALLET" <(journalctl -u "$UNIT_NAME" -n 200 --no-pager) 2>/dev/null; then
        echo
        echo "  YOUR RECOVERY PHRASE (write it down, then forget this terminal):"
        grep -A1 "NEW WALLET" <(journalctl -u "$UNIT_NAME" -n 200 --no-pager) | tail -1
        echo
    fi
    echo "  phrase file : $DATA_DIR/wallet.mnemonic  (0600, user $SERVICE_USER)"
fi
echo "  data        : $DATA_DIR"
echo "  status      : curl -s http://127.0.0.1:8642/api/status | head -c 400"
echo "  logs        : journalctl -u $UNIT_NAME -f"
echo
echo "The node is bound to 127.0.0.1 only. See DEPLOY.md before exposing it:"
echo "it has no authentication and anyone who reaches it can spend the faucet."
