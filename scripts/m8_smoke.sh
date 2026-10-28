#!/bin/bash
# M8 center smoke test: agent forwards sealed events to the center; the
# center aggregates by host and serves authenticated queries.
set -u
PW=123456
SECRET=center-shared-secret-123
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
s pkill -x edr-center
sleep 0.5
s rm -rf /tmp/edr-center-data /tmp/edr-events.jsonl

echo "$PW" | sudo -S nohup /tmp/edr-center --listen 127.0.0.1:7080 \
    --data-dir /tmp/edr-center-data --shared-secret "$SECRET" >/tmp/center.log 2>&1 &
sleep 1

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --bpf --policy /tmp/m4.json \
    --event-path /tmp/edr-events.jsonl --center-url http://127.0.0.1:7080/v0/center/ingest \
    --center-secret $SECRET --run-for 8s >/tmp/ao.jsonl 2>/tmp/ae.txt &"
sleep 2
for i in $(seq 1 40); do /bin/true; done
sleep 8

echo "=== center log ==="; cat /tmp/center.log
echo "=== hosts (aggregated) ==="
/tmp/edrctl center hosts --url http://127.0.0.1:7080 --secret "$SECRET"
echo "=== events (limit 3) ==="
/tmp/edrctl center events --url http://127.0.0.1:7080 --secret "$SECRET" --limit 3
echo "=== negative: wrong secret ==="
/tmp/edrctl center hosts --url http://127.0.0.1:7080 --secret wrong-secret
echo "exit=$?"

s pkill -x edr-agent
s pkill -x edr-center
echo DONE
