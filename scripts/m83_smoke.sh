#!/bin/bash
# M8.3 orchestration smoke test: operator creates+approves a kill action at the
# center; the agent polls, executes it, and reports the result.
set -u
PW=123456
SECRET=center-shared-secret-123
U=http://127.0.0.1:7080
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
s pkill -x edr-center
sleep 0.5
s rm -rf /tmp/edr-center-data

echo "$PW" | sudo -S nohup /tmp/edr-center --listen 127.0.0.1:7080 \
    --data-dir /tmp/edr-center-data --shared-secret "$SECRET" >/tmp/center.log 2>&1 &
sleep 1

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --bpf --host hostA --enforce \
    --center-url http://127.0.0.1:7080/v0/center/ingest --center-secret $SECRET \
    --run-for 20s >/tmp/ao.jsonl 2>/tmp/ae.txt &"
sleep 3

cp -f /bin/sleep /tmp/edr-victim
/tmp/edr-victim 60 &
VP=$!
echo "victim pid=$VP"
sleep 1

echo "=== operator: create kill action ==="
CREATED=$(/tmp/edrctl center actions create --url "$U" --secret "$SECRET" --host hostA --action kill --pid "$VP" --reason "m83 smoke")
echo "$CREATED"
ID=$(echo "$CREATED" | sed -n 's/.*"id": "\([^"]*\)".*/\1/p' | head -1)

echo "=== operator: approve ==="
/tmp/edrctl center actions approve --url "$U" --secret "$SECRET" "$ID" --by analyst >/dev/null

echo "=== waiting for agent to poll (3s interval) ==="
sleep 6
if pgrep -x edr-victim >/dev/null; then echo "RESULT: VICTIM_ALIVE"; else echo "RESULT: VICTIM_KILLED"; fi

echo "=== action state ==="
/tmp/edrctl center actions show --url "$U" --secret "$SECRET" "$ID"
echo "=== rejected-command guard ==="
/tmp/edrctl center actions create --url "$U" --secret "$SECRET" --host hostA --action "rm -rf /" || echo "guard: rejected as expected"

s pkill -x edr-agent
s pkill -x edr-center
echo DONE
