#!/bin/bash
# M2 focused: a tampered signed policy must be rejected on reload.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -f edr-agent
sleep 0.5
echo "$PW" | sudo -S cp /tmp/m2v2.json /tmp/m2t.json
echo "$PW" | sudo -S cp /tmp/m2v2.json.sig /tmp/m2t.json.sig

echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --policy /tmp/m2t.json \
    --pubkey /tmp/edr.key.pub --run-for 7s >/tmp/o2.jsonl 2>/tmp/e2.txt &
sleep 2

echo "--- tamper the signed policy in place ---"
echo "$PW" | sudo -S bash -c 'printf " " >> /tmp/m2t.json'
sleep 0.3
s pkill -HUP -f edr-agent
sleep 1

echo "--- whoami after a rejected reload (must NOT match) ---"
/usr/bin/whoami >/dev/null
sleep 6

echo "=== agent stderr ==="
cat /tmp/e2.txt
echo "=== events (should be empty) ==="
cat /tmp/o2.jsonl
echo "DONE"
