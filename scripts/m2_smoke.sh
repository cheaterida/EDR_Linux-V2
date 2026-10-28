#!/bin/bash
# M2 detection smoke test: sequence rule + signed policy hot-reload.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -f edr-agent
sleep 0.5

echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --policy /tmp/m2.json \
    --pubkey /tmp/edr.key.pub --run-for 16s >/tmp/o.jsonl 2>/tmp/e.txt &
sleep 2

echo "--- trigger sequence: sleep then id ---"
sleep 0.2
/usr/bin/id >/dev/null

echo "--- tamper policy, then SIGHUP (expect: reload rejected) ---"
printf ' ' | s tee -a /tmp/m2.json >/dev/null
sleep 0.3
s pkill -HUP -f edr-agent
sleep 1

echo "--- install signed v2, then SIGHUP (expect: reloaded) ---"
echo "$PW" | sudo -S cp /tmp/m2v2.json /tmp/m2.json
echo "$PW" | sudo -S cp /tmp/m2v2.json.sig /tmp/m2.json.sig
sleep 0.3
s pkill -HUP -f edr-agent
sleep 1

echo "--- trigger reloaded rule: whoami ---"
/usr/bin/whoami >/dev/null
sleep 14

echo "=== agent stderr ==="
cat /tmp/e.txt
echo "=== events ==="
cat /tmp/o.jsonl
echo "DONE"
