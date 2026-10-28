#!/bin/bash
# M8.2 case management smoke test: create -> triage -> disposition, persisted.
set -u
PW=123456
SECRET=center-shared-secret-123
s() { echo "$PW" | sudo -S "$@" 2>/dev/null; }

s pkill -x edr-center
sleep 0.5
s rm -rf /tmp/edr-center-data

echo "$PW" | sudo -S nohup /tmp/edr-center --listen 127.0.0.1:7080 \
    --data-dir /tmp/edr-center-data --shared-secret "$SECRET" >/tmp/center.log 2>&1 &
sleep 1

U=http://127.0.0.1:7080
echo "=== create case ==="
CREATED=$(/tmp/edrctl center cases create --url "$U" --secret "$SECRET" --title "suspicious chain on hostA" --severity high)
echo "$CREATED"
CID=$(echo "$CREATED" | sed -n 's/.*"id": "\([^"]*\)".*/\1/p' | head -1)
echo "case id = $CID"

echo "=== advance status ==="
/tmp/edrctl center cases status --url "$U" --secret "$SECRET" "$CID" investigating >/dev/null
echo "=== set disposition ==="
/tmp/edrctl center cases disposition --url "$U" --secret "$SECRET" "$CID" true_positive --note "confirmed C2 beacon" >/dev/null

echo "=== show case ==="
/tmp/edrctl center cases show --url "$U" --secret "$SECRET" "$CID"
echo "=== list cases ==="
/tmp/edrctl center cases list --url "$U" --secret "$SECRET" | head -20

s pkill -x edr-center
echo DONE
