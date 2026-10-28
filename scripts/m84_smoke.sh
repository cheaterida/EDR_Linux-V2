#!/bin/bash
# M8.4 report/export smoke test: ingest events then produce a report and
# CEF/LEEF exports.
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
for i in $(seq 1 40); do /bin/true; done
bash -c 'true'
cp /etc/hostname /tmp/edr-cp-test 2>/dev/null
sleep 0.3
sleep 12

U=http://127.0.0.1:7080
echo "=== report (markdown-relevant JSON) ==="
/tmp/edrctl center report --url "$U" --secret "$SECRET" | head -30
echo "=== CEF export (limit 3) ==="
/tmp/edrctl center export --url "$U" --secret "$SECRET" --format cef --limit 3
echo "=== LEEF export (limit 2) ==="
/tmp/edrctl center export --url "$U" --secret "$SECRET" --format leef --limit 2

s pkill -x edr-agent
s pkill -x edr-center
echo DONE
