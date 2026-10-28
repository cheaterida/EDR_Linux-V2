#!/bin/bash
# M8.1 center correlation smoke test: agent reports to the center; the center
# correlates the host's events into a chain with ATT&CK tags.
set -u
PW=123456
SECRET=center-shared-secret-123
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
s pkill -x edr-center
sleep 0.5
s rm -rf /tmp/edr-center-data

echo "$PW" | sudo -S nohup /tmp/edr-center --listen 127.0.0.1:7080 \
    --data-dir /tmp/edr-center-data --shared-secret "$SECRET" >/tmp/center.log 2>&1 &
sleep 1

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --bpf --host hostA --policy /tmp/m81.json \
    --center-url http://127.0.0.1:7080/v0/center/ingest --center-secret $SECRET \
    --run-for 12s >/tmp/ao.jsonl 2>/tmp/ae.txt &"
sleep 4
for i in $(seq 1 60); do /bin/true; done
bash -c 'true'
cp /etc/hostname /tmp/edr-cp-test 2>/dev/null
sleep 0.3
sleep 12

echo "=== agent stderr ==="; cat /tmp/ae.txt
echo "=== hosts ==="
/tmp/edrctl center hosts --url http://127.0.0.1:7080 --secret "$SECRET"
echo "=== correlations ==="
/tmp/edrctl center correlations --url http://127.0.0.1:7080 --secret "$SECRET"

s pkill -x edr-agent
s pkill -x edr-center
echo DONE
