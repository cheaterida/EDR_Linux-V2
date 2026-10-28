#!/bin/bash
# Response completion smoke test: nft block + rollback, quarantine + restore.
# Uses nft_block (a scoped drop rule) rather than network_isolate to avoid
# cutting the operator's own SSH session.
set -u
PW=123456
SOCK=/run/edr/agent.sock
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
sleep 0.5
s rm -f /run/edr/admin.key "$SOCK"
s rm -rf /tmp/edr-q /tmp/edr-qdir
mkdir -p /tmp/edr-q
echo payload > /tmp/edr-q/x

echo "$PW" | sudo -S nohup /tmp/edr-agent --enforce --nft-enabled --nft-table edrchk \
    --quarantine-dir /tmp/edr-qdir --socket "$SOCK" --admin-key /run/edr/admin.key \
    --run-for 30s >/tmp/ao.jsonl 2>/tmp/ae.txt &
sleep 2

TOKEN=$(echo "$PW" | sudo -S /tmp/edrctl admin token enforce-toggle --key-file /run/edr/admin.key 2>/dev/null)
echo "token=${TOKEN:0:16}..."

echo "=== nft_block 203.0.113.9:4444 ==="
T=$(echo "$PW" | sudo -S /tmp/edrctl admin token enforce-toggle --key-file /run/edr/admin.key 2>/dev/null)
s /tmp/edrctl --socket "$SOCK" response nft_block --addr 203.0.113.9 --port 4444 --token "$T"
sleep 1
echo "--- ruleset ---"; s nft list table inet edrchk 2>&1 | head -8

echo "=== nft rollback ==="
T=$(echo "$PW" | sudo -S /tmp/edrctl admin token enforce-toggle --key-file /run/edr/admin.key 2>/dev/null)
s /tmp/edrctl --socket "$SOCK" nft rollback --token "$T"
sleep 1
s nft list table inet edrchk 2>&1 | head -2 || echo "table removed"

echo "=== quarantine ==="
T=$(echo "$PW" | sudo -S /tmp/edrctl admin token enforce-toggle --key-file /run/edr/admin.key 2>/dev/null)
s /tmp/edrctl --socket "$SOCK" response quarantine --path /tmp/edr-q/x --token "$T"
sleep 1
[ -e /tmp/edr-q/x ] && echo "PRESENT" || echo "QUARANTINED"
echo "--- list ---"; s /tmp/edrctl --socket "$SOCK" quarantine list

echo "=== restore ==="
T=$(echo "$PW" | sudo -S /tmp/edrctl admin token enforce-toggle --key-file /run/edr/admin.key 2>/dev/null)
s /tmp/edrctl --socket "$SOCK" quarantine restore /tmp/edr-q/x --token "$T"
sleep 1
[ -e /tmp/edr-q/x ] && echo "RESTORED" || echo "MISSING"

echo "--- agent stderr ---"; cat /tmp/ae.txt
s pkill -x edr-agent
echo DONE
