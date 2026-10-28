#!/bin/bash
# EDR functional test - part 1: environment, detection, audit, enforcement,
# control plane, self-protection, stability/resources.
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
trap stop_agent EXIT

start_agent(){ # $1=log, rest=extra args
  local log=$1; shift
  nohup "$E/edr-agent" --bpf --policy /etc/edr/policy.json --socket "$S" \
    --admin-key /etc/edr/admin.key "$@" >"$log" 2>&1 &
  local i
  for i in $(seq 1 24); do sleep 0.5; [ -S "$S" ] && return 0; done
  return 1
}

has_rule(){ grep -aq "\"$2\"" "$1" 2>/dev/null && ok "$3" "$2" || no "$3" "$2 missing"; }

rm -rf "$T"; mkdir -p "$T/watch" "$T/emptyproc"; chmod 755 "$T"
stop_agent
mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf 2>/dev/null

sec "A. 环境与安装"
V=$("$E/edrctl" version 2>&1); case "$V" in *v2.0.0*) ok "env:version" "$V";; *) no "env:version" "$V";; esac
[ -x "$E/edr-agent" ] && ok "env:agent-bin" || no "env:agent-bin"
[ -f /etc/edr/policy.json ] && ok "env:policy" || no "env:policy"
[ -s /etc/edr/admin.key ] && ok "env:admin-key" || no "env:admin-key"
grep -q bpf /sys/kernel/security/lsm && ok "env:lsm-bpf" "$(cat /sys/kernel/security/lsm)" || no "env:lsm-bpf"
command -v bpftool >/dev/null && ok "env:bpftool" || sk "env:bpftool" "missing"
command -v python3 >/dev/null && ok "env:python3" || no "env:python3"
RL=$("$E/edrctl" policy validate /etc/edr/policy.json 2>&1); echo "$RL" | grep -q 'policy OK' && ok "env:policy-valid" "$RL" || no "env:policy-valid" "$RL"

sec "B. 采集与检测（审计档，无强制）"
if start_agent "$T/detect.log" --watch "$T/watch,/etc/cron.d" --masquerade-interval 2s \
   --event-path "$T/detect-events.jsonl" --anchor-file "$T/detect-anchor.json"; then
  ok "detect:startup" "socket up"
else
  no "detect:startup" "$(tail -3 "$T/detect.log" | tr '\n' ' ')"
fi
bash -c 'echo /dev/tcp/1.2.3.4/4444' >/dev/null 2>&1
cp -f /bin/sleep "$T/watch/edr-x" 2>/dev/null; "$T/watch/edr-x" 2 >/dev/null 2>&1
LD_PRELOAD=/tmp/nope.so /bin/sleep 2 >/dev/null 2>&1
python3 -c 'import os; os.setuid(0)' >/dev/null 2>&1
python3 -c 'import os; os.setgid(0)' >/dev/null 2>&1
cp -f /bin/sleep "$T/watch/kworker" 2>/dev/null; "$T/watch/kworker" 20 >/dev/null 2>&1 &
cp /etc/hostname "$T/watch/drop" >/dev/null 2>&1
touch /etc/cron.d/edr-ft-test 2>/dev/null; rm -f /etc/cron.d/edr-ft-test 2>/dev/null
cp -f /bin/true "$T/watch/suidx" 2>/dev/null; chmod +s "$T/watch/suidx" 2>/dev/null
command -v setcap >/dev/null && setcap cap_net_raw+ep "$T/watch/edr-x" >/dev/null 2>&1
command -v nsenter >/dev/null && nsenter -t 1 -m true >/dev/null 2>&1
rm -f /var/log/edr-ft-does-not-exist 2>/dev/null
bpftool map list >/dev/null 2>&1
sleep 4
for r in HOST-REVSHELL-DEVTCP HOST-EXEC-FROM-TMP HOST-LD-PRELOAD HOST-PRIVESC-SETUID \
         HOST-PRIVESC-SETGID HOST-MASQUERADE-KTHREAD HOST-TMP-DROP HOST-CRON-PERSIST \
         HOST-CHMOD-SUID HOST-BPF-OP HOST-ANTIFORENSIC; do
  has_rule "$T/detect-events.jsonl" "$r" "detect:$r"
done
if command -v setcap >/dev/null; then has_rule "$T/detect-events.jsonl" HOST-SETCAP "detect:HOST-SETCAP"; else sk "detect:HOST-SETCAP" "setcap missing"; fi
if command -v nsenter >/dev/null; then has_rule "$T/detect-events.jsonl" HOST-NSENTER "detect:HOST-NSENTER"; else sk "detect:HOST-NSENTER" "nsenter missing"; fi
sk "detect:HOST-MODULE-LOAD" "module load deliberately not exercised"
sk "detect:HOST-SEQ-DOWNLOAD-EXEC" "sequence engine covered by capability tests"
stop_agent

sec "C. 审计完整性"
OUT=$("$E/edrctl" events verify "$T/detect-events.jsonl" --anchor-file "$T/detect-anchor.json" 2>&1); RC=$?
{ [ $RC -eq 0 ] && echo "$OUT" | grep -q 'ok=true' && echo "$OUT" | grep -q 'anchor: consistent'; } \
  && ok "audit:verify" "$(echo "$OUT" | head -1)" || no "audit:verify" "rc=$RC $(echo "$OUT" | head -1)"
cp "$T/detect-events.jsonl" "$T/tampered.jsonl"; sed -i '2d' "$T/tampered.jsonl"
OUT2=$("$E/edrctl" events verify "$T/tampered.jsonl" --anchor-file "$T/detect-anchor.json" 2>&1); RC2=$?
{ [ $RC2 -ne 0 ] || echo "$OUT2" | grep -q 'ok=false'; } \
  && ok "audit:tamper-detected" "$(echo "$OUT2" | head -2 | tr '\n' ' ')" || no "audit:tamper-detected" "tamper not detected"

sec "D. 强制响应（--enforce --nft-enabled）"
if start_agent "$T/enf.log" --enforce --nft-enabled \
   --event-path "$T/enf-events.jsonl" --anchor-file "$T/enf-anchor.json"; then
  ok "enf:startup" "socket up"
else no "enf:startup" "$(tail -3 "$T/enf.log" | tr '\n' ' ')"; fi

cp -f /bin/sleep "$T/victim"; "$T/victim" 60 >/dev/null 2>&1 & VP=$!
sleep 0.3
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" response kill --pid "$VP" --token "$TOK" 2>&1)
sleep 0.5
if [ -e "/proc/$VP" ] && [ "$(awk '{print $3}' "/proc/$VP/stat" 2>/dev/null)" != "Z" ]; then no "enf:kill" "$RES"; else ok "enf:kill" "pid $VP gone"; fi

echo secret > "$T/qfile"
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" response quarantine --path "$T/qfile" --token "$TOK" 2>&1)
[ ! -e "$T/qfile" ] && ok "enf:quarantine" "moved to quarantine" || no "enf:quarantine" "$RES"
"$E/edrctl" --socket "$S" quarantine list 2>/dev/null | grep -q qfile && ok "enf:quarantine-list" || no "enf:quarantine-list"
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" quarantine restore "$T/qfile" --token "$TOK" 2>&1)
[ -e "$T/qfile" ] && ok "enf:quarantine-restore" "restored" || no "enf:quarantine-restore" "$RES"

if command -v nft >/dev/null; then
  TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
  RES=$("$E/edrctl" --socket "$S" response nft_block --addr 203.0.113.9 --port 4444 --token "$TOK" 2>&1)
  sleep 0.3
  nft list table inet edr 2>/dev/null | grep -q 203.0.113.9 && ok "enf:nft-block" || no "enf:nft-block" "$RES"
  TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
  "$E/edrctl" --socket "$S" nft rollback --token "$TOK" >/dev/null 2>&1
  sleep 0.3
  nft list table inet edr 2>/dev/null | grep -q 203.0.113.9 && no "enf:nft-rollback" "rule still present" || ok "enf:nft-rollback"
else sk "enf:nft-block" "nft missing"; sk "enf:nft-rollback" "nft missing"; fi

echo x > "$T/perm"; chmod 0777 "$T/perm"
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" response fix_permissions --path "$T/perm" --token "$TOK" 2>&1)
MODE=$(stat -c '%a' "$T/perm" 2>/dev/null)
[ "$MODE" = "600" ] && ok "enf:fix-permissions" "mode=$MODE" || no "enf:fix-permissions" "mode=$MODE $RES"

cp -f /bin/sleep "$T/susp"; "$T/susp" 60 >/dev/null 2>&1 & SP=$!
sleep 0.2
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" response process_suspend --pid "$SP" --token "$TOK" 2>&1)
sleep 0.2
ST=$(awk '{print $3}' "/proc/$SP/stat" 2>/dev/null)
[ "$ST" = "T" ] && ok "enf:suspend" "state=T" || no "enf:suspend" "state=$ST $RES"
kill -CONT "$SP" 2>/dev/null; kill -9 "$SP" 2>/dev/null

bash -c "sleep 60 & echo \$! > '$T/child.pid'; wait" >/dev/null 2>&1 & PARENT=$!
sleep 0.4; CHILD=$(cat "$T/child.pid" 2>/dev/null)
TOK=$("$E/edrctl" admin token enforce-toggle --key-file /etc/edr/admin.key 2>/dev/null)
RES=$("$E/edrctl" --socket "$S" response kill_tree --pid "$PARENT" --token "$TOK" 2>&1)
sleep 0.6
PARENT_ALIVE=0; CHILD_ALIVE=0
{ [ -e "/proc/$PARENT" ] && [ "$(awk '{print $3}' "/proc/$PARENT/stat" 2>/dev/null)" != "Z" ]; } && PARENT_ALIVE=1
{ [ -n "$CHILD" ] && [ -e "/proc/$CHILD" ] && [ "$(awk '{print $3}' "/proc/$CHILD/stat" 2>/dev/null)" != "Z" ]; } && CHILD_ALIVE=1
{ [ $PARENT_ALIVE -eq 0 ] && [ $CHILD_ALIVE -eq 0 ]; } && ok "enf:kill-tree" "parent+child gone" || no "enf:kill-tree" "p=$PARENT_ALIVE c=$CHILD_ALIVE $RES"

sudo -u lcz "$E/edrctl" --socket "$S" status >/dev/null 2>&1 && no "ctl:nonroot-denied" "non-root succeeded" || ok "ctl:nonroot-denied"
"$E/edrctl" --socket "$S" status > "$T/status.json" 2>/dev/null && ok "ctl:root-status" || no "ctl:root-status"
TOK=$("$E/edrctl" admin token policy-reload --key-file /etc/edr/admin.key 2>/dev/null)
"$E/edrctl" --socket "$S" policy reload --token "$TOK" >/dev/null 2>&1 && ok "ctl:policy-reload" || no "ctl:policy-reload"
"$E/edrctl" --socket "$S" policy reload --token "$TOK" >/dev/null 2>&1 && no "ctl:token-replay" "replay accepted" || ok "ctl:token-replay" "rejected"
stop_agent

sec "E. 自保护（signal + pidfd + bpf_guard + LSM + 哨兵）"
if start_agent "$T/sp.log" --self-protect --bpf-guard --lsm --enforce \
   --event-path "$T/sp-events.jsonl" --anchor-file "$T/sp-anchor.json"; then
  ok "sp:startup" "socket up"
  grep -aq 'BPF-LSM layer attached' "$T/sp.log" && ok "sp:lsm-attached" || no "sp:lsm-attached"
else no "sp:startup" "$(tail -3 "$T/sp.log" | tr '\n' ' ')"; fi
AG=$(pgrep -x edr-agent | head -1)

OUT=$(python3 -c "import ctypes; l=ctypes.CDLL(None,use_errno=True); r=l.syscall(200,$AG,9); print(r, ctypes.get_errno())" 2>&1)
echo "$OUT" | grep -q '^-1 1$' && ok "sp:tkill-lsm" "$OUT" || no "sp:tkill-lsm" "$OUT"

bash -c "kill -9 $AG" >/dev/null 2>&1
sleep 0.6
pgrep -x edr-agent >/dev/null && ok "sp:kill-blocked" "agent alive" || no "sp:kill-blocked" "agent dead"
grep -aq '"sys_kill"' "$T/sp-events.jsonl" 2>/dev/null && ok "sp:kill-audited" || no "sp:kill-audited"

bash -c "python3 -c 'import os,signal; fd=os.pidfd_open($AG); signal.pidfd_send_signal(fd, signal.SIGKILL)'" >/dev/null 2>&1
sleep 0.6
pgrep -x edr-agent >/dev/null && ok "sp:pidfd-blocked" "agent alive" || no "sp:pidfd-blocked" "agent dead"
grep -aq 'sys_pidfd_send_signal' "$T/sp-events.jsonl" 2>/dev/null && ok "sp:pidfd-audited" || no "sp:pidfd-audited"

AG=$(pgrep -x edr-agent | head -1)
MAPID=""
for id in $(bpftool map list 2>/dev/null | awk '/name agent_pid/{gsub(":","",$1);print $1}'); do
  v=$(bpftool map dump id "$id" 2>/dev/null | grep -oE '"value": [0-9]+' | awk '{print $2}' | head -1)
  [ "$v" = "$AG" ] && MAPID=$id
done
if [ -n "$MAPID" ]; then
  bpftool map update id "$MAPID" key 0 0 0 0 value 0 0 0 0 >/dev/null 2>&1 \
    && no "sp:bpf-map-guard" "tamper allowed" || ok "sp:bpf-map-guard" "EPERM"
else no "sp:bpf-map-guard" "agent_pid map not found"; fi

rm -f /sys/fs/bpf/edrfttest
if bpftool map create /sys/fs/bpf/edrfttest type array key 4 value 4 entries 1 name edrfttest >/dev/null 2>&1; then
  bpftool map update pinned /sys/fs/bpf/edrfttest key 0 0 0 0 value 1 0 0 0 >/dev/null 2>&1 \
    && ok "sp:bpf-unrelated-allowed" || no "sp:bpf-unrelated-allowed" "blocked"
  rm -f /sys/fs/bpf/edrfttest
else sk "sp:bpf-unrelated-allowed" "map create failed"; fi

PROG=$(bpftool prog list 2>/dev/null | awk '/name edr_selfprotect_kill/{gsub(":","",$1);print $1;exit}')
if [ -n "$PROG" ]; then
  bpftool cgroup attach /sys/fs/cgroup ingress id "$PROG" >/dev/null 2>&1 \
    && no "sp:bpf-attach-guard" "attach allowed" || ok "sp:bpf-attach-guard" "EPERM"
  grep -aq bpf_object_guard "$T/sp-events.jsonl" 2>/dev/null && ok "sp:guard-audit" "bpf_object_guard logged" || no "sp:guard-audit"
else sk "sp:bpf-attach-guard" "prog id not found"; fi

SOS=$(grep -ac 'SELF-PROTECTION ALERT' "$T/sp.log" 2>/dev/null)
[ "$SOS" = "0" ] && ok "sp:sentinel-no-false-sos" || no "sp:sentinel-no-false-sos" "count=$SOS"
stop_agent

sec "F. 稳定性与资源占用"
if start_agent "$T/stab.log" --watch "$T/watch" --masquerade-interval 3s --rootkit-interval 3s \
   --event-path "$T/stab-events.jsonl" --anchor-file "$T/stab-anchor.json"; then
  AG=$(pgrep -x edr-agent | head -1)
  : > "$T/res.txt"
  for i in $(seq 1 8); do ps -o rss=,pcpu= -p "$AG" >> "$T/res.txt" 2>/dev/null; sleep 1; done
  for i in $(seq 1 30); do bash -c 'echo /dev/tcp/1.2.3.4/4444' >/dev/null 2>&1; done
  sleep 1
  "$E/edrctl" --socket "$S" status > "$T/stab-status.json" 2>/dev/null
  RESLINE=$(awk '{rss+=$1; cpu+=$2; if($1>mr)mr=$1; if($2>mc)mc=$2} END{if(NR>0) printf "rss_avg=%dKB rss_max=%dKB cpu_avg=%.1f%% cpu_max=%.1f%%", rss/NR, mr, cpu/NR, mc}' "$T/res.txt")
  info "stab:resource" "$RESLINE"
  DROPS=$(python3 -c "import json;d=json.load(open('$T/stab-status.json'));print(d.get('pipeline_dropped',-1),d.get('bpf_dropped',-1))" 2>/dev/null)
  [ "$DROPS" = "0 0" ] && ok "stab:no-drops" "pipeline=0 bpf=0" || no "stab:no-drops" "drops=$DROPS"
  stop_agent
  start_agent "$T/stab2.log" --event-path "$T/stab-events.jsonl" --anchor-file "$T/stab-anchor.json"
  sleep 1
  stop_agent
  OUT=$("$E/edrctl" events verify "$T/stab-events.jsonl" --anchor-file "$T/stab-anchor.json" 2>&1); RC=$?
  { [ $RC -eq 0 ] && echo "$OUT" | grep -q 'ok=true'; } \
    && ok "stab:chain-continuity" "$(echo "$OUT" | head -1)" || no "stab:chain-continuity" "$(echo "$OUT" | head -2 | tr '\n' ' ')"
else no "stab:startup" "$(tail -3 "$T/stab.log" | tr '\n' ' ')"; fi

stop_agent
echo
echo "SUMMARY | PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
