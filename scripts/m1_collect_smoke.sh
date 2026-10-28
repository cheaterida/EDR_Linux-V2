#!/bin/bash
# M1 collection-expansion smoke test (privesc + inotify + bpf).
set -u
PW=123456
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s rm -rf /tmp/edr-collect
mkdir -p /tmp/edr-collect   # owned by the invoking user so touch works

echo "$PW" | sudo -S nohup /tmp/edr-agent --bpf --watch /tmp/edr-collect \
    --policy /tmp/m1-collect.json --run-for 9s >/tmp/o.jsonl 2>/tmp/e.txt &
sleep 2

# trigger 1: privilege change
echo "$PW" | sudo -S python3 -c 'import os; os.setuid(1000)' 2>/dev/null
# trigger 2: file creation (inotify)
touch /tmp/edr-collect/newfile
# trigger 3: bpf syscalls
echo "$PW" | sudo -S bpftool map list >/dev/null 2>&1

sleep 9
echo "=== agent stderr ==="
cat /tmp/e.txt
echo "=== events by kind (1=exec 4=exit 9=privesc 10/11=module 12=bpf 13=file) ==="
grep -o '"kind":[0-9]*' /tmp/o.jsonl | sort | uniq -c
echo "=== chained events ==="
cat /tmp/o.jsonl
echo "DONE"
