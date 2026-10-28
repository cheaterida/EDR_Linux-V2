#!/bin/bash
# Process-masquerade detection smoke test: a userspace process named like a
# kernel thread (kworker) is flagged and chained.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
sleep 0.5
s rm -f /tmp/ev.jsonl

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --policy /tmp/masq.json \
    --event-path /tmp/ev.jsonl --masquerade-interval 2s --bpf=false >/tmp/ao.jsonl 2>/tmp/ae.txt &" 
sleep 2

# create a userspace process whose comm looks like a kernel thread
cp -f /bin/sleep /tmp/kworker
/tmp/kworker 30 &
sleep 5

echo "=== agent stderr ==="; cat /tmp/ae.txt
echo "=== masquerade events ==="
s sh -c 'grep -o "\"kind\":14[^}]*}" /tmp/ev.jsonl | head -2'
s sh -c 'grep -o "\"kind\":[0-9]*" /tmp/ev.jsonl | sort | uniq -c'

s pkill -x edr-agent
pkill -x kworker 2>/dev/null
echo DONE
