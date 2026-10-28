#!/bin/bash
# Install the EDR lab layout. Run as root from the extracted bundle directory.
#   /opt/edr/bin       binaries
#   /etc/edr           policy.json, admin.key, center.secret
#   /var/lib/edr       agent events/anchor
#   /var/lib/edr-center center store
#   /run/edr           runtime sockets/heartbeats
# Services are installed but NOT enabled or started.
set -eu

if [ "$(id -u)" != "0" ]; then
    echo "install_lab.sh must run as root" >&2
    exit 1
fi

PREFIX=/opt/edr
here=$(cd "$(dirname "$0")" && pwd)

install -d -m 0755 "$PREFIX/bin" "$PREFIX/docs"
install -d -m 0750 /etc/edr /var/lib/edr /var/lib/edr-center /run/edr

for b in "$here"/bin/*; do
    install -m 0755 "$b" "$PREFIX/bin/"
done
install -m 0644 "$here"/configs/policy.json /etc/edr/policy.json
install -m 0644 "$here"/systemd/*.service /etc/systemd/system/
# Recreate /run/edr across reboots (/run is a tmpfs).
if [ -f "$here"/tmpfiles/edr.conf ]; then
    install -m 0644 "$here"/tmpfiles/edr.conf /usr/lib/tmpfiles.d/edr.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/edr.conf || true
fi

# Admin token key (hex, 32 bytes).
if [ ! -s /etc/edr/admin.key ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/edr/admin.key
    chmod 0600 /etc/edr/admin.key
fi
# Audit-chain HMAC key (hex, 32 bytes) so event content cannot be forged
# without the key. Use `edrctl events verify --key-file /etc/edr/audit.key`.
if [ ! -s /etc/edr/audit.key ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/edr/audit.key
    chmod 0600 /etc/edr/audit.key
fi
# Center shared secret (raw, used to HMAC-sign ingest/queries).
if [ ! -s /etc/edr/center.secret ]; then
    head -c 32 /dev/urandom | base64 | tr -d '\n' > /etc/edr/center.secret
    chmod 0600 /etc/edr/center.secret
fi

# Default agent run options (empty = audit mode).
if [ ! -f /etc/edr/agent.env ]; then
    cat > /etc/edr/agent.env <<'EOF'
# Extra edr-agent flags. Empty = audit mode (no enforcement, no self-protection).
# Hardened host example:
# EDR_OPTIONS=--enforce --self-protect --bpf-guard --lsm --datapath-socket /run/edr/datapath.sock --nft-enabled
EDR_OPTIONS=
EOF
    chmod 0644 /etc/edr/agent.env
fi

# Notification config (empty = disabled until you add channels).
if [ ! -f /etc/edr/notify.json ]; then
    printf '{}\n' > /etc/edr/notify.json
    chmod 0644 /etc/edr/notify.json
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "installed to $PREFIX"
echo "  binaries: $(ls "$PREFIX/bin" | tr '\n' ' ')"
echo "  policy:   /etc/edr/policy.json"
echo "  admin:    /etc/edr/admin.key"
echo "  secret:   /etc/edr/center.secret"
echo
echo "services (not started): edr-agent edr-center edr-datapath edr-orchestrator"
echo "start audit mode:   systemctl start edr-center edr-datapath edr-agent"
echo "stop:               see docs/DEPLOY-LAB.md (self-protection blocks SIGTERM)"
