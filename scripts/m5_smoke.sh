#!/bin/bash
# M5 self-protection smoke test: a *root* attacker cannot kill the agent;
# the attack is blocked and the attacker counter-killed.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
sleep 0.5
s rm -f /tmp/edr-events.jsonl /tmp/kres.txt

echo "$PW" | sudo -S sh -c "nohup /tmp/edr-agent --bpf --self-protect --policy /tmp/m4.json \
    --event-path /tmp/edr-events.jsonl --run-for 16s >/tmp/ao.jsonl 2>/tmp/ae.txt &"
sleep 3

AGENT=$(pgrep -x edr-agent | head -1)
echo "agent pid=$AGENT"

echo "--- root attacker: sudo kill -9 agent ---"
echo "$PW" | sudo -S bash -c "kill -9 $AGENT; echo rc=\$? > /tmp/kres.txt" >/dev/null 2>&1 &
sleep 2
if [ -f /tmp/kres.txt ]; then
  echo "attacker rc: $(cat /tmp/kres.txt)"
else
  echo "attacker terminated before writing (counter-killed)"
fi
if pgrep -x edr-agent >/dev/null; then echo "AGENT_ALIVE"; else echo "AGENT_DEAD"; fi

sleep 14
echo "--- agent stderr ---"; cat /tmp/ae.txt
echo "--- SOS check (must be empty) ---"
grep -c "SELF-PROTECTION ALERT\|SELF-PROTECTION SOS" /tmp/ae.txt || true
echo "--- events by kind ---"
s sh -c 'grep -o "\"kind\":[0-9]*" /tmp/edr-events.jsonl | sort | uniq -c'
echo "--- self-protection event ---"
s sh -c 'grep -o "sys_kill[^}]*}" /tmp/edr-events.jsonl | head -1' || echo "(none)"

s pkill -x edr-agent
echo DONE
