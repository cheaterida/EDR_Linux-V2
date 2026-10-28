#!/bin/bash
# Build a self-contained lab bundle (binaries + configs + systemd + installer).
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
source /tmp/opencode/goenv.sh 2>/dev/null || true
source "$HOME/.cargo/env" 2>/dev/null || true
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}

echo "== build Go binaries =="
make dist >/dev/null
echo "== build Rust datapath =="
( cd datapath && cargo build --release >/dev/null )

OUT="$ROOT/dist/lab"
rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/configs" "$OUT/systemd" "$OUT/tmpfiles"
cp "$ROOT"/dist/edr-agent "$ROOT"/dist/edrctl "$ROOT"/dist/edr-center "$ROOT"/dist/edr-orchestrator "$ROOT"/dist/edr-preflight "$OUT/bin/"
cp "$ROOT"/datapath/target/release/edr-datapath "$OUT/bin/"
cp "$ROOT"/configs/policy.host.json "$OUT/configs/policy.json"
cp "$ROOT"/configs/policy.lab.json "$OUT/configs/policy.lab.json"
cp "$ROOT"/configs/notify.example.json "$OUT/configs/notify.example.json"
cp "$ROOT"/deploy/systemd/*.service "$OUT/systemd/"
cp "$ROOT"/deploy/tmpfiles/*.conf "$OUT/tmpfiles/"
cp "$ROOT"/scripts/install_lab.sh "$OUT/install_lab.sh"
chmod +x "$OUT/install_lab.sh" "$OUT/bin/"*

tar czf "$ROOT/dist/edr-lab.tar.gz" -C "$OUT" .
echo "== bundle: $ROOT/dist/edr-lab.tar.gz =="
tar tzf "$ROOT/dist/edr-lab.tar.gz"
