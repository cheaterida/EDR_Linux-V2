# 实验部署与人工测试方案（云主机安全 + 运营中心）

> 目标：把新 EDR 部署到测试机，采用**类似云主机的主机安全**定位（通用主机安全，不做业务特调），
> 供你进行**人工实机测试**（重点是真实强制效果，而非仅遥测）。

---

## 0. 适配性判断（先回答"是否符合云主机安全 + 运营中心稳定"）

**结论：架构定位符合，作为"通用主机安全框架 + 运营中心"是成立的；但作为生产云主机产品还需补齐若干运维/规则维度。**

匹配云主机安全的部分：
- 单机 Agent 采集**与业务无关的通用行为**（进程/文件/网络/提权/模块/自保护），不绑定任何业务。
- **精确强制**：kill/quarantine/nft/fanotify-deny 只在规则命中时作用于明确目标。
- **审计可信**：哈希链 + 顺序/降级校验 + 锚定 + 中心连续性（gaps）。
- **运营中心闭环**：接入/存储/查询 → 关联/ATT&CK → 案件 → 报告 → 处置编排（封闭枚举 + 审批）。
- **默认安全**：dry-run 默认、危险开关显式开启、admin token 防重放、socket 0600。

距"生产云主机"仍需注意（不阻塞现阶段实机测试）：
- 检测**规则库偏薄**（当前为通用主机基线，非完整规则集）。
- 缺 **Prometheus 指标 / 告警渠道（webhook/email/syslog）**；观测主要靠中心与 CLI。
- **审计 HMAC 未在 agent 接线**（当前为哈希链）。
- 自保护未覆盖 LSM、`pidfd_send_signal`、`/proc/pid/mem`、cgroup.freeze、bpf map 写保护等；测试机未启用 BPF LSM。
- 采集未覆盖 `execveat/clone3/openat2/mount/namespace`。
- 中心存储为单机文件、传输为 HMAC 明文 HTTP（无 mTLS）。

**对人工实机测试：已就绪。** 下面给出部署与剧本。

---

## 1. 部署拓扑与目录

单机（测试机）同时运行 Agent、Center、Datapath：

```
/opt/edr/bin/{edr-agent,edrctl,edr-center,edr-orchestrator,edr-preflight,edr-datapath}
/etc/edr/{policy.json,admin.key,center.secret}
/var/lib/edr/{events.jsonl,anchor.json,quarantine/}
/var/lib/edr-center/{hosts/,cases/,actions/}
/run/edr/{agent.sock,datapath.sock,*.heartbeat}
```

端口/套接字：agent 控制面 `/run/edr/agent.sock`；datapath `/run/edr/datapath.sock`；center `127.0.0.1:7080`。

## 2. 安装

在开发机：

```bash
make package-lab          # 生成 dist/edr-lab.tar.gz（含二进制/配置/systemd/安装脚本）
scp dist/edr-lab.tar.gz lcz@192.168.214.144:/tmp/
```

在测试机（root）：

```bash
mkdir -p /tmp/edr-lab && tar xzf /tmp/edr-lab.tar.gz -C /tmp/edr-lab
sudo /tmp/edr-lab/install_lab.sh
```

安装脚本会创建 `/opt/edr`、`/etc/edr`、`/var/lib/edr*`、`/run/edr`，生成 `admin.key`（hex）与 `center.secret`，
安装 systemd 单元但**不启用、不启动**。

## 3. 运行模式

| 模式 | 命令要点 | 说明 |
|---|---|---|
| 审计（安全起点） | `edr-agent --bpf --policy /etc/edr/policy.json --event-path ... --socket ... --admin-key ...` | 响应 dry-run，仅记录/告警 |
| 强制 | 追加 `--enforce` | kill/quarantine/nft 真正执行 |
| 自保护 | 追加 `--self-protect` | 精确拦截针对 agent 的信号/内存操作（含反击杀） |
| BPF 对象守卫 | 追加 `--bpf-guard` | **只拦对 agent 自身 BPF 对象**（按 `edr_own_ids` id 精确）的 update/delete/freeze 与 prog/link detach；主机其他 BPF 工具不受影响 |
| 自身完整性哨兵 | 开 `--self-protect` 或 `--bpf-guard` 即运行；`--self-check-dir /opt/edr` | 心跳停滞 / agent_pid 被改 / 二进制被替换 / 安装目录消失 → SOS + 告警 |
| LSM 强化（可选） | 追加 `--lsm`（需内核 `lsm=…bpf`） | 内核权威层拦截信号/ptrace，覆盖 kprobe 未挂的路径（如 `tkill`）；内核不支持时优雅跳过，不影响 kprobe 主路径 |
| 文件同步拦截 | 启动 `edr-datapath` + agent `--datapath-socket` | fanotify FAN_OPEN_PERM |
| 上报中心 | 追加 `--center-url http://127.0.0.1:7080/v0/center/ingest --center-secret-file /etc/edr/center.secret` | 事件入中心 |

systemd 启动：单元默认**审计档**（`/etc/edr/agent.env` 内 `EDR_OPTIONS=` 为空）。切换强制档只需编辑该文件：

```bash
# /etc/edr/agent.env
EDR_OPTIONS=--enforce --self-protect --datapath-socket /run/edr/datapath.sock --nft-enabled
# 如需上报中心再加：
# EDR_OPTIONS="$EDR_OPTIONS --center-url http://127.0.0.1:7080/v0/center/ingest --center-secret-file /etc/edr/center.secret"
```

```bash
sudo systemctl start edr-center
sudo systemctl start edr-datapath
sudo systemctl start edr-agent
```

告警渠道配置在 `/etc/edr/notify.json`（默认 `{}` = 关闭）。示例见 `configs/notify.example.json`
（webhook generic/dingtalk/wechat_work/feishu、远程 syslog RFC5424、email）。每个渠道有 `min_severity` 过滤。

## 4. 停止 / 重启（重要）

- **未开 `--self-protect`**：`systemctl stop edr-agent` / `kill` 正常。
- **已开 `--self-protect`**：SIGTERM/SIGKILL 会被 BPF 精确拦截，`systemctl stop` 会卡住。必须走受控停机：

```bash
TOKEN=$(/opt/edr/bin/edrctl admin token shutdown --key-file /etc/edr/admin.key)
/opt/edr/bin/edrctl --socket /run/edr/agent.sock shutdown --token "$TOKEN"
```

- datapath / center 无自保护，正常 `systemctl stop` 即可。

## 5. 人工测试剧本

> 约定：`EDR=/opt/edr/bin`，`SOCK=/run/edr/agent.sock`，`T()` 取新令牌：
> `T(){ sudo $EDR/edrctl admin token enforce-toggle --key-file /etc/edr/admin.key; }`

### 场景 A — 采集与门禁
```bash
$EDR/edrctl version
$EDR/edr-agent --once                     # 合成事件，验证管线与哈希链输出
```
预期：`--once` 输出带 `chain.seq/prev_hash/hash` 的 JSONL。

### 场景 B — 采集 + 检测（审计）
1) 启动（审计）：
```bash
sudo $EDR/edr-agent --bpf --policy /etc/edr/policy.json \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket $SOCK --admin-key /etc/edr/admin.key &
```
2) 触发通用规则：
```bash
bash -c 'echo /dev/tcp/1.2.3.4/4444'      # 命中 HOST-REVSHELL-DEVTCP（审计：告警）
cp /etc/hostname /tmp/x                    # 命中 HOST-TMP-DROP（文件创建）
```
3) 查看：
```bash
sudo $EDR/edrctl --socket $SOCK events query --limit 5
```
预期：出现对应 `rule_id` 与 `decision:alert/block` 的事件。

### 场景 C — 强制响应（kill / quarantine / nft）
```bash
# kill（对可控进程）
cp -f /bin/sleep /tmp/edr-victim; /tmp/edr-victim 60 &  VP=$!
sudo $EDR/edrctl --socket $SOCK response kill --pid $VP --token "$(T)"
pgrep -x edr-victim || echo KILLED

# quarantine + 恢复
echo x | sudo tee /tmp/edr-q-test >/dev/null
sudo $EDR/edrctl --socket $SOCK response quarantine --path /tmp/edr-q-test --token "$(T)"
sudo $EDR/edrctl --socket $SOCK quarantine list
sudo $EDR/edrctl --socket $SOCK quarantine restore /tmp/edr-q-test --token "$(T)"

# nft 阻断 + 回滚（用 nft_block，勿用 isolate 以免断网）
sudo $EDR/edrctl --socket $SOCK response nft_block --addr 203.0.113.9 --port 4444 --token "$(T)"
sudo nft list table inet edr | grep 203.0.113.9
sudo $EDR/edrctl --socket $SOCK nft rollback --token "$(T)"
```
预期：victim 被杀；quarantine 往返；nft 规则出现后回滚删除。
（注意：**每个动作都要取新 token**，同 token 复用会被防重放拒绝。）

### 场景 D — fanotify 同步拒绝（datapath）
```bash
sudo mkdir -p /tmp/edr-watch; echo topsecret | sudo tee /tmp/edr-watch/secret >/dev/null
sudo /opt/edr/bin/edr-datapath --socket /run/edr/datapath.sock --watch /tmp/edr-watch &
sudo $EDR/edr-agent --bpf --policy <(cat /etc/edr/policy.json) ...  # 或使用 LAB 策略
cat /tmp/edr-watch/secret      # 预期：Operation not permitted
```
> LAB 用策略见 `configs/policy.lab.json`（对 `/tmp/edr-watch/` 前缀 `fanotify_deny`）。datapath 在收到策略前不拦截。

### 场景 E — 自保护（精确 + 反击杀）
```bash
sudo $EDR/edr-agent --bpf --self-protect --policy /etc/edr/policy.json --socket $SOCK --admin-key /etc/edr/admin.key &
AP=$(pgrep -x edr-agent)
sudo kill -9 $AP ; echo "rc=$?"       # 预期 rc=1(EPERM)，且发起者被反击杀
pgrep -x edr-agent >/dev/null && echo AGENT_ALIVE
# 停止：用 /v0/shutdown（见第 4 节）
```

### 场景 F — 审计完整性（HMAC + 锚定）
```bash
# 启用 HMAC 的 agent（安装后 /etc/edr/audit.key 由安装脚本生成）：
#   --audit-key-file /etc/edr/audit.key
sudo $EDR/edrctl events verify /var/lib/edr/events.jsonl --key-file /etc/edr/audit.key \
  --anchor-file /var/lib/edr/anchor.json          # 预期 ok=true + hmac 校验
sudo $EDR/edrctl events verify /var/lib/edr/events.jsonl   # 不带 key → hmac_mismatch（证明 HMAC 生效）
# 远程锚定（中心充当锚点，攻击者无法本地改写）：
#   agent: --anchor-url http://127.0.0.1:7080/v0/center/anchor --anchor-secret-file /etc/edr/center.secret --anchor-every 1
sudo $EDR/edrctl events verify /var/lib/edr/events.jsonl --key-file /etc/edr/audit.key \
  --anchor-url http://127.0.0.1:7080/v0/center/anchor --secret-file /etc/edr/center.secret
# 篡改/截断副本后再验证，预期 hash_mismatch / anchor_truncation
```

### 场景 G — 控制面认证
```bash
$EDR/edrctl --socket $SOCK status                       # 非 root / 非 0 uid：403
sudo $EDR/edrctl --socket $SOCK status                  # root：正常
sudo $EDR/edrctl --socket $SOCK policy reload --token "$(T)"
sudo $EDR/edrctl --socket $SOCK policy reload --token "<上次同一 token>"   # 预期 403 重放
```

### 场景 H — 运营中心闭环
```bash
sudo systemctl start edr-center
# agent 追加 --center-url ... --center-secret-file /etc/edr/center.secret
SEC=$(sudo cat /etc/edr/center.secret)
sudo $EDR/edrctl center hosts --url http://127.0.0.1:7080 --secret "$SEC"
sudo $EDR/edrctl center events --url http://127.0.0.1:7080 --secret "$SEC" --limit 5
sudo $EDR/edrctl center correlations --url http://127.0.0.1:7080 --secret "$SEC"
# 案件
CID=$(sudo $EDR/edrctl center cases create --url http://127.0.0.1:7080 --secret "$SEC" --title test --severity high | sed -n 's/.*"id": "\([^"]*\)".*/\1/p')
sudo $EDR/edrctl center cases status --url http://127.0.0.1:7080 --secret "$SEC" "$CID" investigating
# 处置编排
AID=$(sudo $EDR/edrctl center actions create --url http://127.0.0.1:7080 --secret "$SEC" --host "$(hostname)" --action kill --pid <PID> | sed -n 's/.*"id": "\([^"]*\)".*/\1/p')
sudo $EDR/edrctl center actions approve --url http://127.0.0.1:7080 --secret "$SEC" "$AID" --by analyst
sleep 5; sudo $EDR/edrctl center actions show --url http://127.0.0.1:7080 --secret "$SEC" "$AID"
# 报告/导出
sudo $EDR/edrctl center report --url http://127.0.0.1:7080 --secret "$SEC"
sudo $EDR/edrctl center export --url http://127.0.0.1:7080 --secret "$SEC" --format cef --limit 3
```
预期：hosts 有本机；events/correlations 返回数据；案件状态机推进；action 变 `completed`（`killed via pidfd`）；report/CEF 正常。

### 场景 I — HA（可选）
```bash
# 单机模拟：两个 orchestrator 观测同一 stale peer，仅租约持有者重启
/opt/edr/bin/edr-orchestrator --instance edr-a --peer edr-b --run-dir /run/edr --restart-cmd "touch /tmp/edr-restarted" &
/opt/edr/bin/edr-orchestrator --instance edr-c --peer edr-b --run-dir /run/edr --restart-cmd "touch /tmp/edr-restarted" &
```

### 场景 J — 稳定性观察
- 长跑 10min+，`edrctl status` 观察 `pipeline_dropped/bpf_dropped` 是否持续为 0。
- 重启 agent 后确认链从 anchor 续接（`chain_seq` 递增、中心 `gaps` 为 0）。
- 观察 fanotify 是否影响业务延迟（datapath 无显式延迟指标，可对比命令耗时）。

### 场景 K — 告警渠道
```bash
# 1) 起一个本地接收端
python3 - <<'PY' &
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); b=self.rfile.read(n)
        open('/tmp/hook.log','a').write(b.decode()+'\n')
        self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',18080),H).serve_forever()
PY
# 2) 配置 webhook（min_severity=low 便于观察）
sudo sh -c 'cat > /etc/edr/notify.json <<JSON
{"webhooks":[{"url":"http://127.0.0.1:18080/","format":"generic","min_severity":"low"}]}
JSON'
# 3) 启动 agent（审计）并触发命中事件
sudo /opt/edr/bin/edr-agent --bpf --policy /etc/edr/policy.json --notify-config /etc/edr/notify.json \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key --run-for 8s &
sleep 3; sudo id >/dev/null          # 触发提权类事件
sleep 6
cat /tmp/hook.log                     # 预期：收到含 rule_id/severity 的 JSON
```
预期：`/tmp/hook.log` 出现 POST 正文；低于 `min_severity` 的事件不会发送。

### 场景 L — BPF 对象守卫 + 完整性哨兵
```bash
# 只开 BPF 对象守卫（不需 self-protect）；先清干净残留实例
if [ -S /run/edr/agent.sock ]; then
  TOK=$(sudo /opt/edr/bin/edrctl admin token shutdown --key-file /etc/edr/admin.key)
  sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock shutdown --token "$TOK"
  sleep 2
fi
sudo /opt/edr/bin/edr-agent --bpf --bpf-guard --self-check-dir /opt/edr \
  --policy /etc/edr/policy.json \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key >/tmp/g.log 2>&1 &
sleep 2; AG=$(pgrep -x edr-agent); echo "agent=$AG"

# 找到 agent 自己的 agent_pid map（值 == agent pid）
MAPID=$(for id in $(sudo bpftool map list | awk '/name agent_pid/{gsub(":","",$1);print $1}'); do
  v=$(sudo bpftool map dump id "$id" 2>/dev/null | grep -oE '"value": [0-9]+' | awk '{print $2}' | head -1)
  [ "$v" = "$AG" ] && echo "$id"; done)

# 1) 篡改 agent 自身 map → 预期 Operation not permitted，且值不变
sudo bpftool map update id "$MAPID" key 0 0 0 0 value 0 0 0 0 ; echo "rc=$?"

# 2) 无关 map → 预期成功（证明没有过度封锁）
sudo rm -f /sys/fs/bpf/edrtest
sudo bpftool map create /sys/fs/bpf/edrtest type array key 4 value 4 entries 1 name edrtest
sudo bpftool map update pinned /sys/fs/bpf/edrtest key 0 0 0 0 value 1 0 0 0 ; echo "rc=$?"

# 3) 审计留痕（应出现 HOST-SELF-PROTECT-TAMPER / kind=self_protect）
sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock events query --rule HOST-SELF-PROTECT-TAMPER --limit 1

# 4) attach/relink 族：尝试 BPF_PROG_ATTACH 自有程序 → 预期被拦 + 守卫事件
PROG=$(sudo bpftool prog list | awk '/name edr_selfprotect_kill/{gsub(":","",$1);print $1;exit}')
sudo bpftool cgroup attach /sys/fs/cgroup ingress id "$PROG"; echo "rc=$?"
sudo grep -a bpf_object_guard /var/lib/edr/events.jsonl | tail -1   # detail 应为 8 (BPF_PROG_ATTACH)
```
预期：①返回 `Operation not permitted`（-EPERM）且 `agent_pid` 未被清零；②返回成功；③有 `self_protect` 审计事件；④attach 被拦且守卫事件 `detail=8`。
> 说明：`--bpf-guard` 默认**只拦截 + 告警**；加 `--self-protect` 会对发起者**反击杀**（`EDR_GUARD_KILL`）。
> 受控停机同场景 E：`edrctl admin token shutdown` → `edrctl ... shutdown --token`。

### 场景 M — pidfd 信号 + LSM 强化
```bash
# 前台启动（自保护 + bpf-guard + LSM），随后在另一终端做下面两项
sudo /opt/edr/bin/edr-agent --bpf --self-protect --bpf-guard --lsm \
  --policy /etc/edr/policy.json --event-path /var/lib/edr/events.jsonl \
  --anchor-file /var/lib/edr/anchor.json --socket /run/edr/agent.sock \
  --admin-key /etc/edr/admin.key
AG=$(pgrep -x edr-agent)

# 1) pidfd_send_signal（绕过 kill/tgkill 的另一条路）
bash -c "python3 -c 'import os,signal; fd=os.pidfd_open($AG); signal.pidfd_send_signal(fd, signal.SIGKILL)'; echo rc=\$?"
# 预期：发起进程被反击杀（Killed），agent 存活

# 2) tkill（kprobe 未覆盖；仅当 LSM 已启用时被拦）
bash -c "python3 -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); print(l.syscall(200,$AG,9), ctypes.get_errno())'"
# 预期：LSM 已启用 → -1 / errno=1(EPERM)，且发起者存活；未启用 LSM → 信号送达（agent 若未另设防护会被杀）
```
启用 LSM（一次性，需重启）：
```bash
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"/' /etc/default/grub
sudo update-grub && sudo reboot
cat /sys/kernel/security/lsm   # 应含 bpf
```
> 启动顺序（已消除窗口）：LSM 层在**武装之前**挂载；武装时 `SetGuardConfig` **先写 LSM 配置、再写 kprobe 配置**。因此不存在"kprobe 已武装但 LSM 未挂"的窗口——kprobe 未覆盖的 `tkill` 等路径从武装那一刻起即受 LSM 保护。

### 场景 N — rootkit 跨源检测
```bash
# 1) 干净主机：确定性检查（隐藏进程/模块 + syscall 完整性）应无告警
sudo /opt/edr/bin/edr-agent --bpf --policy /etc/edr/policy.json --rootkit-interval 5s \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key &
sleep 12
# 预期：stderr 无 "rootkit finding"；agent 存活
sudo pkill -x edr-agent; sleep 1

# 2) 正向验证（无需真 rootkit）：用空 proc-root 伪造"隐藏进程"
sudo mkdir -p /tmp/emptyproc
sudo /opt/edr/bin/edr-agent --bpf --policy /etc/edr/policy.json \
  --rootkit-interval 2s --rootkit-min-lifetime 1s \
  --proc-root /tmp/emptyproc --sys-root /tmp/emptyproc \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key &
sleep 1; sleep 30 &          # 长命进程，会被 tracker 学到
sleep 6
sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock events query --rule HOST-ROOTKIT-HIDDEN-PROCESS --limit 2
# 预期：出现 hidden_process 事件（链文件中含 HOST-ROOTKIT-HIDDEN-PROCESS）
```
> 隐藏进程/模块、syscall 完整性是**默认开启的确定性检查**；隐藏连接依赖 `/proc/net/tcp` 时序、在繁忙主机易误报，默认关闭，用 `--rootkit-connections` 开启。

### 场景 O — 攻击面加固验证（红队视角）
```bash
# 1) 可选严格模块加载拦截（对抗 root+LKM）
sudo /opt/edr/bin/edr-agent --bpf --strict-modules --policy /etc/edr/policy.json \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key &
sleep 2
sudo insmod /tmp/nope.ko ; echo "rc=$?"          # 预期 EPERM
sudo grep -a sys_init_module /var/lib/edr/events.jsonl | tail -1   # 守卫留痕

# 2) datapath 存活哨兵（杀掉数据面 → SOS）
sudo /opt/edr/bin/edr-datapath --socket /run/edr/datapath.sock --watch /tmp &
sudo /opt/edr/bin/edr-agent --bpf --self-protect --datapath-socket /run/edr/datapath.sock \
  --policy /etc/edr/policy.json --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key >/tmp/dp-agent.log 2>&1 &
sleep 3; sudo pkill -x edr-datapath
sleep 6; grep -a 'SELF-PROTECTION SOS' /tmp/dp-agent.log   # 预期出现 SOS

# 3) token 不再走 argv（避免被同机用户从 /proc/pid/cmdline 读取）
sudo /opt/edr/bin/edrctl admin token enforce-toggle --key-file /etc/edr/admin.key > /tmp/tok
sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock response kill --pid <PID> --token-file /tmp/tok
```
> 说明：`--strict-modules` 仅适用于**不在运行时加载模块**的主机；否则会拦截合法 `modprobe`。
> 中心侧：动作响应已做 HMAC 体签名（`X-EDR-Response-Signature`），请求签名覆盖 query；生产建议叠加 mTLS。

## 6. 已知限制（与本轮测试相关）
- **重启后 `/run` 会被清空**：`/run/edr` 由 `tmpfiles.d/edr.conf` 在开机时重建，agent 也会自动创建该目录；
  若手工命令仍报 `bind ... no such file or directory`，先 `sudo mkdir -p /run/edr && sudo chmod 750 /run/edr`。
- **判断 agent 是否存活**（自保护档下 `pgrep` 结果也可靠）：
  `pgrep -a edr-agent`；或 `sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock status`（能返回即存活）。
- 自保护开启后**必须用 `/v0/shutdown` 停机**（SIGTERM 被拦）。
- **链连续性**：若不传 `--anchor-file`，agent 每次启动会**新建一条链**并追加到同一事件文件，
  之后 `edrctl events verify` 会因 seq 从 1 重新开始而报 `seq_gap`。请始终传 `--anchor-file`
  （systemd 单元已内置），或每轮测试前清理 `events.jsonl`。
- `network_isolate` 会切断出站：**仅在可承受断网的机器上测**，或改用 `nft_block`。
- BPF LSM 未启用（测试机 `lsm=` 未含 bpf）：自保护以 kprobe override 为主。
- 中心为单机文件存储、HMAC 明文 HTTP（无 mTLS）。

## 7. 一键冒烟（脚本化）
仓库提供分场景脚本（开发机执行即可，脚本内含 sudo）：
`scripts/m1_collect_smoke.sh`、`m1_datapath_smoke.sh`、`m2_smoke.sh`、`m3_smoke.sh`、`m5_smoke.sh`、
`m6_smoke.sh`、`m7_smoke.sh`、`m81_smoke.sh`、`m82_smoke.sh`、`m83_smoke.sh`、`m84_smoke.sh`、`m_resp_smoke.sh`、`masq_smoke.sh`。
