#!/bin/bash
# M4 audit smoke test: run with a file sink + anchor, then verify
# clean / tampered / downgraded / truncated logs.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
sleep 0.5
s rm -f /tmp/edr-events.jsonl /tmp/edr-events.jsonl.1 /tmp/edr-anchor.json /tmp/base.jsonl /tmp/t1.jsonl /tmp/t2.jsonl /tmp/t3.jsonl

echo "$PW" | sudo -S sh -c 'nohup /tmp/edr-agent --bpf --policy /tmp/m4.json \
    --event-path /tmp/edr-events.jsonl --anchor-file /tmp/edr-anchor.json \
    --anchor-every 1 --run-for 6s >/tmp/ao.jsonl 2>/tmp/ae.txt &'
sleep 2
echo "=== generate activity ==="
for i in $(seq 1 40); do /bin/true; done
for i in 1 2 3 4 5; do echo x > /tmp/edr-a$i; done
sleep 5
echo "=== agent stderr ==="; cat /tmp/ae.txt
echo "=== log lines ==="; s wc -l /tmp/edr-events.jsonl
echo "=== anchor ==="; s cat /tmp/edr-anchor.json; echo

s cp /tmp/edr-events.jsonl /tmp/base.jsonl

echo "=== 1) clean verify (with anchor) ==="
s /tmp/edrctl events verify /tmp/base.jsonl --anchor-file /tmp/edr-anchor.json

echo "=== 2) tampered body ==="
s cp /tmp/base.jsonl /tmp/t1.jsonl
s sed -i '3s/"comm":"[^"]*"/"comm":"tampered"/' /tmp/t1.jsonl
s /tmp/edrctl events verify /tmp/t1.jsonl

echo "=== 3) downgraded (chain field stripped) ==="
s cp /tmp/base.jsonl /tmp/t2.jsonl
s python3 -c "import json; l=open('/tmp/t2.jsonl').read().splitlines(); d=json.loads(l[2]); d.pop('chain',None); l[2]=json.dumps(d); open('/tmp/t2.jsonl','w').write(chr(10).join(l)+chr(10))"
s /tmp/edrctl events verify /tmp/t2.jsonl

echo "=== 4) truncated tail (anchor should catch) ==="
s cp /tmp/base.jsonl /tmp/t3.jsonl
s sh -c 'head -n -2 /tmp/t3.jsonl > /tmp/t3b.jsonl && mv /tmp/t3b.jsonl /tmp/t3.jsonl'
s /tmp/edrctl events verify /tmp/t3.jsonl --anchor-file /tmp/edr-anchor.json

s pkill -x edr-agent
echo DONE
