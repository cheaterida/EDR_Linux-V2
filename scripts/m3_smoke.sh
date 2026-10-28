#!/bin/bash
# M3 response smoke test: kill via datapath (target-validated) + file quarantine.
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-agent
s pkill -x edr-datapath
sleep 0.5
echo "$PW" | sudo -S nohup /tmp/edr-datapath --socket /run/edr/datapath.sock >/tmp/dp.log 2>&1 &
sleep 1

echo "=== kill demo (via datapath, target-validated) ==="
cp -f /bin/sleep /tmp/edr-victim
chmod +x /tmp/edr-victim
echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --datapath-socket /run/edr/datapath.sock \
    --policy /tmp/m3-kill.json --enforce --run-for 10s >/tmp/o1.jsonl 2>/tmp/e1.txt &
sleep 3
/tmp/edr-victim 60 &
sleep 3
if pgrep -x edr-victim >/dev/null; then echo "RESULT: VICTIM_ALIVE"; else echo "RESULT: VICTIM_KILLED"; fi
sleep 6
echo "--- agent stderr ---"; cat /tmp/e1.txt
echo "--- events ---"; cat /tmp/o1.jsonl
echo "--- datapath log (tail) ---"; tail -2 /tmp/dp.log

echo "=== quarantine demo ==="
rm -rf /tmp/edr-q /tmp/edr-qdir
mkdir -p /tmp/edr-q
echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --watch /tmp/edr-q \
    --policy /tmp/m3-quarantine.json --enforce --quarantine-dir /tmp/edr-qdir \
    --run-for 10s >/tmp/o2.jsonl 2>/tmp/e2.txt &
sleep 3
echo payload > /tmp/edr-q/dropper.sh
sleep 3
if [ -e /tmp/edr-q/dropper.sh ]; then echo "RESULT: FILE_PRESENT"; else echo "RESULT: FILE_QUARANTINED"; fi
echo "--- quarantine dir ---"; ls -la /tmp/edr-qdir/ 2>/dev/null | tail -4
sleep 6
echo "--- agent stderr ---"; cat /tmp/e2.txt
echo "--- events ---"; cat /tmp/o2.jsonl

s pkill -x edr-agent
s pkill -x edr-datapath
echo DONE
