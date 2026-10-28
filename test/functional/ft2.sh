#!/bin/bash
# EDR functional test - part 2: ops center, alerting, rootkit.
E=/opt/edr/bin
S=/run/edr/agent.sock
T=/tmp/edr-ft
PASS=0; FAIL=0; SKIP=0
ok(){ echo "PASS | $1 | ${2:-}"; PASS=$((PASS+1)); }
no(){ echo "FAIL | $1 | ${2:-}"; FAIL=$((FAIL+1)); }
sk(){ echo "SKIP | $1 | ${2:-}"; SKIP=$((SKIP+1)); }
info(){ echo "INFO | $1 | ${2:-}"; }
sec(){ echo; echo "### $1"; }

stop_agent(){
  local i TOK
  for i in 1 2 3; do
    if [ -S "$S" ]; then
      TOK=$("$E/edrctl" admin token shutdown --key-file /etc/edr/admin.key 2>/dev/null)
      "$E/edrctl" --socket "$S" shutdown --token "$TOK" >/dev/null 2>&1
    fi
    sleep 1
    pgrep -x edr-agent >/dev/null || break
    pkill -x edr-agent 2>/dev/null
    sleep 1
  done
  rm -f "$S" 2>/dev/null
}
stop_center(){ pkill -x edr-center 2>/dev/null; sleep 1; }
trap 'stop_agent; stop_center; pkill -f "http.server.HTTPServer" 2>/dev/null; pkill -f "18080" 2>/dev/null' EXIT

start_agent(){
  local log=$1; shift
  nohup "$E/edr-agent" --bpf --policy /etc/edr/policy.json --socket "$S" \
    --admin-key /etc/edr/admin.key "$@" >"$log" 2>&1 &
  local i
  for i in $(seq 1 24); do sleep 0.5; [ -S "$S" ] && return 0; done
  return 1
}

rm -rf "$T"; mkdir -p "$T"; chmod 755 "$T"
stop_agent; stop_center

sec "G. 运营中心闭环"
rm -rf "$T/center"
nohup "$E/edr-center" --listen 127.0.0.1:7080 --data-dir "$T/center" \
  --shared-secret-file /etc/edr/center.secret >"$T/center.log" 2>&1 &
sleep 1
python3 - <<PY >/dev/null 2>&1
import socket, time
for _ in range(30):
    try:
        s=socket.create_connection(("127.0.0.1",7080),0.3); s.close(); break
    except Exception: time.sleep(0.2)
PY
SEC=$(cat /etc/edr/center.secret)
U=http://127.0.0.1:7080
if start_agent "$T/center-agent.log" --enforce --event-path "$T/center-events.jsonl" \
   --anchor-file "$T/center-anchor.json" \
   --center-url "$U/v0/center/ingest" --center-secret-file /etc/edr/center.secret; then
  ok "center:agent-startup" "socket up"
else no "center:agent-startup" "$(tail -3 "$T/center-agent.log" | tr '\n' ' ')"; fi
bash -c 'echo /dev/tcp/1.2.3.4/4444' >/dev/null 2>&1
cp -f /bin/sleep "$T/cx" 2>/dev/null; "$T/cx" 2 >/dev/null 2>&1
sleep 2
HOSTN=$(hostname)
"$E/edrctl" center hosts --url "$U" --secret "$SEC" > "$T/hosts.json" 2>&1
grep -q "$HOSTN" "$T/hosts.json" && ok "center:hosts" "$HOSTN" || no "center:hosts" "$(head -c 160 "$T/hosts.json")"
"$E/edrctl" center events --url "$U" --secret "$SEC" --limit 20 > "$T/cevents.json" 2>&1
grep -q HOST-REVSHELL "$T/cevents.json" && ok "center:events" || no "center:events" "$(head -c 160 "$T/cevents.json")"
"$E/edrctl" center correlations --url "$U" --secret "$SEC" --limit 20 > "$T/corr.json" 2>&1
[ -s "$T/corr.json" ] && ok "center:correlations" || no "center:correlations" "$(head -c 160 "$T/corr.json")"

"$E/edrctl" center cases create --url "$U" --secret "$SEC" --title ft-test --severity high > "$T/case.json" 2>&1
CID=$(python3 -c "import json;print(json.load(open('$T/case.json')).get('id',''))" 2>/dev/null)
[ -n "$CID" ] && ok "center:case-create" "id=$CID" || no "center:case-create" "$(head -c 160 "$T/case.json")"
"$E/edrctl" center cases list --url "$U" --secret "$SEC" > "$T/cases.json" 2>&1
grep -q "$CID" "$T/cases.json" && ok "center:case-list" || no "center:case-list"
"$E/edrctl" center cases status --url "$U" --secret "$SEC" "$CID" investigating >/dev/null 2>&1 \
  && ok "center:case-status" "investigating" || no "center:case-status"
"$E/edrctl" center cases disposition --url "$U" --secret "$SEC" "$CID" true_positive >/dev/null 2>&1 \
  && ok "center:case-disposition" "true_positive" || no "center:case-disposition"

cp -f /bin/sleep "$T/cv"; "$T/cv" 90 >/dev/null 2>&1 & CV=$!
sleep 0.3
"$E/edrctl" center actions create --url "$U" --secret "$SEC" --host "$HOSTN" --action kill --pid "$CV" > "$T/action.json" 2>&1
AID=$(python3 -c "import json;print(json.load(open('$T/action.json')).get('id',''))" 2>/dev/null)
[ -n "$AID" ] && ok "center:action-create" "id=$AID" || no "center:action-create" "$(head -c 160 "$T/action.json")"
"$E/edrctl" center actions approve --url "$U" --secret "$SEC" "$AID" --by analyst >/dev/null 2>&1 \
  && ok "center:action-approve" || no "center:action-approve"
sleep 6
"$E/edrctl" center actions show --url "$U" --secret "$SEC" "$AID" > "$T/action-show.json" 2>&1
grep -q '"state": *"completed"' "$T/action-show.json" && ok "center:action-completed" || no "center:action-completed" "$(head -c 200 "$T/action-show.json")"
[ -e "/proc/$CV" ] && kill -9 "$CV" 2>/dev/null

"$E/edrctl" center report --url "$U" --secret "$SEC" > "$T/report.txt" 2>&1
[ -s "$T/report.txt" ] && ok "center:report" "bytes=$(wc -c < "$T/report.txt")" || no "center:report"
"$E/edrctl" center export --url "$U" --secret "$SEC" --format cef --limit 3 > "$T/cef.txt" 2>&1
grep -q 'CEF:' "$T/cef.txt" && ok "center:export-cef" || no "center:export-cef" "$(head -c 160 "$T/cef.txt")"
stop_agent; stop_center

sec "H. 告警渠道（webhook + 严重度过滤）"
rm -f "$T/hook.log"
python3 - <<PY >"$T/hook-srv.log" 2>&1 &
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); b=self.rfile.read(n)
        open("$T/hook.log","a").write(b.decode()+chr(10))
        self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",18080),H).serve_forever()
PY
sleep 1
cat > /etc/edr/notify.json <<JSON
{"webhooks":[{"url":"http://127.0.0.1:18080/","format":"generic","min_severity":"high"}]}
JSON
start_agent "$T/notify.log" --notify-config /etc/edr/notify.json \
  --event-path "$T/notify-events.jsonl" --anchor-file "$T/notify-anchor.json" >/dev/null 2>&1
python3 -c 'import os; os.setuid(0)' >/dev/null 2>&1
bash -c 'echo /dev/tcp/1.2.3.4/4444' >/dev/null 2>&1
sleep 3
grep -q HOST-REVSHELL "$T/hook.log" 2>/dev/null && ok "notify:high-delivered" || no "notify:high-delivered" "$(head -c 160 "$T/hook.log" 2>/dev/null)"
grep -q HOST-PRIVESC-SETUID "$T/hook.log" 2>/dev/null && no "notify:severity-filter" "medium event leaked" || ok "notify:severity-filter" "medium filtered"
stop_agent
pkill -f 'HTTPServer' 2>/dev/null
printf '{}\n' > /etc/edr/notify.json

sec "I. rootkit 跨源检测"
start_agent "$T/rk-clean.log" --rootkit-interval 3s \
  --event-path "$T/rk-clean-events.jsonl" --anchor-file "$T/rk-clean-anchor.json" >/dev/null 2>&1
sleep 12
CNT=$(grep -ac 'rootkit finding' "$T/rk-clean.log" 2>/dev/null)
[ "$CNT" = "0" ] && ok "rootkit:clean-no-false-positive" || no "rootkit:clean-no-false-positive" "findings=$CNT"
stop_agent

rm -rf "$T/emptyproc"; mkdir -p "$T/emptyproc"
start_agent "$T/rk-pos.log" --rootkit-interval 2s --rootkit-min-lifetime 1s \
  --proc-root "$T/emptyproc" --sys-root "$T/emptyproc" \
  --event-path "$T/rk-pos-events.jsonl" --anchor-file "$T/rk-pos-anchor.json" >/dev/null 2>&1
sleep 1
sleep 45 >/dev/null 2>&1 & RKS=$!
sleep 6
CNT=$(grep -ac 'rootkit finding' "$T/rk-pos.log" 2>/dev/null)
[ "${CNT:-0}" -ge 1 ] && ok "rootkit:positive-detect" "findings=$CNT" || no "rootkit:positive-detect" "none"
grep -aq HOST-ROOTKIT-HIDDEN-PROCESS "$T/rk-pos-events.jsonl" 2>/dev/null \
  && ok "rootkit:rule-and-audit" || no "rootkit:rule-and-audit"
kill "$RKS" 2>/dev/null
stop_agent

echo
echo "SUMMARY | PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
