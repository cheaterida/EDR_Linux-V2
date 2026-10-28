#!/bin/bash
# M1 datapath smoke test (runs on the test machine as user lcz with sudo).
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s mkdir -p /tmp/edr-watch /run/edr
printf 'topsecret\n' | sudo -S tee /tmp/edr-watch/secret >/dev/null 2>&1
s pkill -f edr-datapath
sleep 0.5

echo "$PW" | sudo -S nohup /tmp/edr-datapath --socket /run/edr/datapath.sock --watch /tmp/edr-watch >/tmp/dp.log 2>&1 &
sleep 1.5
echo "=== datapath startup log ==="
cat /tmp/dp.log
echo "=== socket ==="
ls -la /run/edr/datapath.sock 2>&1

echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --datapath-socket /run/edr/datapath.sock --policy /tmp/m1-datapath.json --run-for 8s >/tmp/o.jsonl 2>/tmp/e.txt &
sleep 2

echo "=== read watched file (expect Permission denied) ==="
cat /tmp/edr-watch/secret
echo "cat-exit=$?"

sleep 8
echo "=== agent stderr ==="
cat /tmp/e.txt
echo "=== datapath log ==="
cat /tmp/dp.log
echo "=== agent chained events ==="
cat /tmp/o.jsonl
s pkill -f edr-datapath
echo "DONE"
