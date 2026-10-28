#!/bin/bash
E=/opt/edr/bin; S=/run/edr/agent.sock; T=/tmp/edr-res
rm -rf "$T"; mkdir -p "$T"
if [ -S "$S" ]; then
  TOK=$("$E/edrctl" admin token shutdown --key-file /etc/edr/admin.key 2>/dev/null)
  "$E/edrctl" --socket "$S" shutdown --token "$TOK" >/dev/null 2>&1; sleep 2
fi
pkill -x edr-agent 2>/dev/null; sleep 1
nohup "$E/edr-agent" --bpf --self-protect --bpf-guard --lsm \
  --rootkit-interval 30s --masquerade-interval 15s \
  --policy /etc/edr/policy.json \
  --event-path "$T/ev.jsonl" --anchor-file "$T/an.json" \
  --socket "$S" --admin-key /etc/edr/admin.key >"$T/agent.log" 2>&1 &
sleep 10
AG=$(pgrep -x edr-agent | head -1)
grep -aE 'registered|guards armed|BPF-LSM' "$T/agent.log"
# one matched event so the chain is non-empty and exercises response_result
bash -c 'echo /dev/tcp/1.2.3.4/4444' >/dev/null 2>&1
sleep 2
read u1 s1 < <(awk '{print $14, $15}' "/proc/$AG/stat")
RSS1=$(awk '/VmRSS/{print $2}' "/proc/$AG/status")
sleep 20
read u2 s2 < <(awk '{print $14, $15}' "/proc/$AG/stat")
RSS2=$(awk '/VmRSS/{print $2}' "/proc/$AG/status")
HZ=$(getconf CLK_TCK)
CPU=$(awk -v u1="$u1" -v s1="$s1" -v u2="$u2" -v s2="$s2" -v hz="$HZ" \
  'BEGIN{d=(u2+s2)-(u1+s1); printf "%.2f", d/(hz*20)*100}')
echo "RESOURCE | steady_state_cpu=${CPU}% rss_start=${RSS1}KB rss_end=${RSS2}KB"
"$E/edrctl" --socket "$S" status > "$T/status.json" 2>/dev/null
python3 -c "import json;d=json.load(open('$T/status.json'));print('STATUS | pipeline_dropped=%s bpf_dropped=%s chain_seq=%s'%(d.get('pipeline_dropped'),d.get('bpf_dropped'),d.get('chain_seq')))"
TOK=$("$E/edrctl" admin token shutdown --key-file /etc/edr/admin.key)
"$E/edrctl" --socket "$S" shutdown --token "$TOK" >/dev/null 2>&1
sleep 2; pkill -x edr-agent 2>/dev/null
echo "AUDIT | $("$E/edrctl" events verify "$T/ev.jsonl" --anchor-file "$T/an.json" 2>&1 | head -1)"
echo "AUDIT_ANCHOR | $("$E/edrctl" events verify "$T/ev.jsonl" --anchor-file "$T/an.json" 2>&1 | grep 'anchor:' | head -1)"
