#!/bin/bash
# M6 control-plane smoke test: peer-credential gating + admin-token gated reload.
set -u
PW=123456
SOCK=/run/edr/agent.sock
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
sleep 0.5
s rm -f "$SOCK" /tmp/edr-events.jsonl /tmp/edr-events.jsonl.1 /run/edr/admin.key
s mkdir -p /run/edr /var/lib/edr

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --bpf --policy /tmp/m4.json \
    --event-path /tmp/edr-events.jsonl --socket $SOCK --admin-key /run/edr/admin.key \
    --allowed-uids 0 --run-for 18s >/tmp/ao.jsonl 2>/tmp/ae.txt &"
sleep 3
# widen socket mode so a non-root client can reach the peercred check.
s chmod 0666 "$SOCK"
for i in $(seq 1 30); do /bin/true; done
sleep 1

echo "=== 1) non-root (uid 1000) status -> expect 403 ==="
/tmp/edrctl --socket "$SOCK" status
echo "exit=$?"

echo "=== 2) root status ==="
s /tmp/edrctl --socket "$SOCK" status

echo "=== 3) root events query (summary) ==="
s /tmp/edrctl --socket "$SOCK" events query --limit 3 --format summary

echo "=== 4) root policy show ==="
s /tmp/edrctl --socket "$SOCK" policy show

echo "=== 5) admin token issued, then reload ==="
TOKEN=$(echo "$PW" | sudo -S /tmp/edrctl admin token policy-reload --key-file /run/edr/admin.key 2>/dev/null)
echo "token=${TOKEN:0:16}..."
s /tmp/edrctl --socket "$SOCK" policy reload --token "$TOKEN"

echo "=== 6) replay same token -> expect 403 ==="
s /tmp/edrctl --socket "$SOCK" policy reload --token "$TOKEN"
echo "exit=$?"

echo "=== agent stderr ==="; cat /tmp/ae.txt
sleep 12
s pkill -x edr-agent
echo DONE
