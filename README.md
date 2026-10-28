# EDR Linux v2 — 通用 Linux 主机安全与运营中心

> 面向云主机 / 服务器的 **主机入侵检测与响应（EDR）**：CO-RE eBPF 采集 + Go 控制面 + Rust 数据面，
> 覆盖「检测 → 精确响应 → 可信审计 → 自保护 → 控制面 → HA → 运营中心」完整闭环。
>
> 本仓库是旧项目 `EDR-Linux-master`（v0.9.1）的**迁移重构**。新版本不做业务特调，
> 定位为**通用主机安全框架 + 稳定运营中心**，并以**可验证性**为第一约束。

- 许可证：MIT（见 [`LICENSE`](LICENSE)）
- 当前能力矩阵：**48 / 48**（由测试生成，见 [`docs/capability-matrix.md`](docs/capability-matrix.md)）
- 基线策略：**26 条通用主机规则 + 1 条序列**（`configs/policy.host.json`）

---

## 目录

1. [项目定位](#1-项目定位)
2. [核心能力](#2-核心能力)
3. [架构](#3-架构)
4. [仓库结构](#4-仓库结构)
5. [环境要求](#5-环境要求)
6. [构建](#6-构建)
7. [初始化与部署](#7-初始化与部署)
8. [运行模式](#8-运行模式)
9. [使用 CLI](#9-使用-cli)
10. [策略](#10-策略)
11. [运营中心](#11-运营中心)
12. [审计与完整性](#12-审计与完整性)
13. [自保护与 rootkit 检测](#13-自保护与-rootkit-检测)
14. [告警渠道](#14-告警渠道)
15. [测试与质量](#15-测试与质量)
16. [安全模型与已知边界](#16-安全模型与已知边界)
17. [排错](#17-排错)
18. [文档索引](#18-文档索引)
19. [开发约定](#19-开发约定)

---

## 1. 项目定位

**通用 Linux 主机安全 + 运营中心**，适合云主机 / 服务器 / 实验环境：

- **不做业务特调**：规则基于通用主机行为（提权、持久化、反取证、rootkit、文件篡改等），
  不绑定任何具体业务进程或路径。
- **精确、最小强制**：自保护与响应只作用于**明确目标**（目标进程 == Agent、自有 BPF 对象 id、
  明确的 PID/文件/地址），避免旧项目"拦截所有信号 / 所有 bpf()"造成的自伤。
- **可验证性优先**：能力矩阵由测试生成、CI 失败于矩阵过期；文档描述与代码路径一致。
- **分级响应**：高危且可精确处置的行为自动拦截；对通用主机可能误伤的（如模块加载、
  IO 型隐藏连接）默认**仅告警**，可通过策略/开关升级。
- **诚实的安全边界**：本地 root + 恶意内核模块可以压制任何主机 EDR；本项目的目标是
  **抬高攻击成本、让被压制可见（SOS/告警/审计）、并检出实际攻击行为**。详见
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)。

旧项目的主要问题（本版本针对性修正）：文档宣称与运行时漂移、自保护过宽误杀、
`vmlinux.h` 内核强绑定、审计锚定语义不完整。

---

## 2. 核心能力

| 领域 | 能力 |
|---|---|
| 采集 | CO-RE eBPF：exec / fork / exit / connect / 文件操作 / 提权 / 模块 / bpf()；内核态采集 **exe + argv**；`/proc` 按需富化；inotify 兜底 |
| 检测 | 26 条通用规则 + 序列规则（A→B 时间窗）+ allow 覆盖；进程伪装检测；rootkit 跨源一致性 |
| 响应 | kill（pidfd + 身份校验）/ kill_tree / quarantine(+restore) / fix_permissions / process_suspend / nft_block / network_isolate(+restore) |
| 自保护 | 精确信号/内存拦截（kill/tgkill/rt_sigqueueinfo/**pidfd_send_signal**/ptrace/process_vm_*）；**BPF 对象守卫**（按 id：map update/delete/freeze、prog/link detach、PROG_ATTACH/LINK_CREATE/LINK_UPDATE）；可选 **BPF-LSM**（task_kill/ptrace）；可选 **严格模块加载拦截**；完整性哨兵 + SOS；丢事件告警 |
| 审计 | SHA-256 链 + **可选 HMAC**；seq 连续 + 拒绝降级 + 文件/远程锚定；轮转校验；`events verify` |
| 控制面 | Unix socket HTTP + `SO_PEERCRED` 白名单 + admin token（nonce 防重放）；支持 `--token-file` |
| 运营中心 | HMAC 接入、按主机存储、链连续性（gaps）、查询、关联/ATT&CK、案件、处置编排（封闭枚举 + 审批 + 轮询执行）、报告、CEF/LEEF |
| 告警 | webhook（generic/dingtalk/wechat_work/feishu）、远程 syslog（RFC5424）、email；严重度过滤 + 异步背压 |
| HA | 心跳状态机 + 单写者租约（防脑裂）+ supervisor 仲裁 + orchestrator 故障切换 |
| 工程 | `make gate` 门禁；能力矩阵由测试生成；lab 一键打包/安装；systemd + tmpfiles |

---

## 3. 架构

```
┌────────────────────────────── 运营中心 edr-center ──────────────────────────────┐
│  HMAC 接入 → 按主机存储 → 链连续性(gaps) → 关联/ATT&CK → 案件 → 处置编排 → 报告/导出 │
│  远程锚点 /v0/center/anchor（单调、响应签名）                                     │
└───────────────────────────────▲─────────────────────────────────────────────────┘
                                │ 事件上报 / 动作轮询（HMAC 请求 + 响应签名）
┌───────────────────────────────┴──────────────── 单机 Agent ─────────────────────┐
│  pipeline: host → enrich(/proc 兜底) → learn → detect(规则+序列) → respond → audit → notify │
│                                                                                  │
│  collect: CO-RE eBPF（含 io_uring/VFS 文件探针）   datapath(Rust): fanotify/pidfd │
│  protect: own BPF 对象守卫 + 精确拦截 + LSM(可选) + 哨兵/丢事件告警 + SOS           │
│  audit:   SHA-256 链(+HMAC) + 文件/远程锚定                                       │
│  control: Unix socket API（SO_PEERCRED + admin token）                            │
└───────────────────────────────▲──────────────────────────────────────────────────┘
                                │ 心跳 + 租约
                        edr-orchestrator（split A/B + supervisor 仲裁）
```

**语言边界**

| 层 | 语言 | 职责 |
|---|---|---|
| 控制面 / 大脑 | Go | 检测、策略、审计、控制面、HA、运营中心、CLI |
| 数据面 | Rust | fanotify 同步决策、pidfd 响应原语、IPC |
| 内核态 | C（CO-RE） | eBPF 探针（tracepoint/kprobe/LSM） |

Rust 与 Go 通过版本化 Unix socket 帧协议通信；Go 使用纯 Go 的 `cilium/ebpf` 加载器（无 cgo）。

---

## 4. 仓库结构

```
cmd/
  edr-agent/        单机 Agent（采集/检测/响应/审计/自保护/控制面）
  edr-center/       运营中心服务端
  edr-orchestrator/ HA 故障切换
  edr-preflight/    只读主机能力预检
  edrctl/           CLI
internal/
  event/ pipeline/ policy/ detect/ audit/ bpf/ collect/ datapath/
  respond/ protect/ integrity/ rootkit/ control/ adminauth/ notify/
  center/ liveness/ lease/ requestauth/ supervisor/ capmatrix/
datapath/           Rust 数据面（fanotify/pidfd/IPC）
deploy/
  systemd/          edr-agent/-center/-datapath/-orchestrator.service
  tmpfiles/         /run/edr 开机重建
configs/            policy.host.json / policy.lab.json / notify.example.json
scripts/            install_lab.sh / package_lab.sh
test/
  capability/       能力矩阵验收（生成 docs/capability-matrix.md）
  functional/       真机功能测试（ft1/ft2/resource）
docs/               OVERVIEW / MODULES / DEPLOY-LAB / THREAT-MODEL / ...
```

---

## 5. 环境要求

| 项 | 要求 |
|---|---|
| 内核 | Linux 5.15+（实测 Ubuntu 24.04，内核 6.17 / 7.0）；需 `CONFIG_BPF_SYSCALL`、BTF、CO-RE |
| 可选 | BPF LSM：内核 `CONFIG_BPF_LSM=y` 且启动参数含 `bpf`（见 §13） |
| 权限 | Agent/datapath 需 **root**（eBPF/fanotify/nft） |
| Go | 1.23+（`go.mod`） |
| Rust | stable（`cargo build --release`） |
| 工具 | `clang`、`bpftool`、`libbpf` 头文件（仅重新生成 BPF 时需要） |
| 可选工具 | `nft`（网络响应）、`python3`（功能测试）、`bpftool`（守卫验证） |

> Makefile 优先使用 `PATH` 中的 `go`，否则回退到 `/home/cheater/go/bin/go`（开发机路径），
> 可按需覆盖：`make GO=/usr/local/go/bin/go gate`。

---

## 6. 构建

```bash
make gate            # gofmt + vet + test + build（离线、无需 root）
make capability      # 生成 docs/capability-matrix.md（当前 48/48）
make test-race       # 竞态检测
make dist            # 构建 5 个入口到 dist/
make datapath-build  # 构建 Rust 数据面
make preflight       # 构建只读能力预检
make package-lab     # 生成 dist/edr-lab.tar.gz（二进制+配置+systemd+安装脚本）
```

**重新生成 BPF**（换内核/改探针时）：

```bash
make bpf-gen         # = make vmlinux + go generate ./internal/bpf/
# vmlinux.h 由当前内核 BTF 生成，不纳入版本控制
```

> 仓库已提交 `internal/bpf/bpf_bpfel.{go,o}` 与 `lsm_bpfel.{go,o}`，普通构建无需 clang。
> 在**目标内核**上重新 `make bpf-gen` 可获得最佳 CO-RE 适配。

---

## 7. 初始化与部署

### 7.1 一键 Lab 安装

在开发机打包：

```bash
make package-lab
scp dist/edr-lab.tar.gz user@HOST:/tmp/
```

在目标机（root）：

```bash
mkdir -p /tmp/edr-lab && tar xzf /tmp/edr-lab.tar.gz -C /tmp/edr-lab
sudo /tmp/edr-lab/install_lab.sh
```

### 7.2 目录布局

```
/opt/edr/bin/        edr-agent edrctl edr-center edr-orchestrator edr-datapath edr-preflight
/etc/edr/            policy.json admin.key center.secret audit.key agent.env notify.json
/var/lib/edr/        events.jsonl anchor.json quarantine/
/var/lib/edr-center/ hosts/ cases/ actions/
/run/edr/            agent.sock datapath.sock *.heartbeat（tmpfiles 开机重建）
```

安装脚本会：

- 安装 systemd 单元（**不启用、不启动**）与 `tmpfiles.d/edr.conf`；
- 生成 `admin.key`（hex）、`center.secret`、`audit.key`（hex，审计 HMAC）；
- 写入默认 `/etc/edr/agent.env`（**审计档**）与空 `notify.json`。

### 7.3 启动

```bash
sudo systemctl start edr-center edr-datapath edr-agent
sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock status
```

单元默认**审计档**（`/etc/edr/agent.env` 中 `EDR_OPTIONS=` 为空）。切换强制档：

```bash
# /etc/edr/agent.env
EDR_OPTIONS=--enforce --self-protect --bpf-guard --lsm --self-check-dir /opt/edr \
  --datapath-socket /run/edr/datapath.sock --nft-enabled
sudo systemctl restart edr-agent
```

### 7.4 停止（重要）

- **未开 `--self-protect`**：`systemctl stop edr-agent` 正常。
- **已开 `--self-protect`**：SIGTERM/SIGKILL 会被精确拦截，`systemctl stop` 会卡住。必须受控停机：

```bash
TOKEN=$(sudo /opt/edr/bin/edrctl admin token shutdown --key-file /etc/edr/admin.key)
sudo /opt/edr/bin/edrctl --socket /run/edr/agent.sock shutdown --token-file <(echo "$TOKEN")
# 或：--token "$TOKEN"
```

- datapath / center 无自保护，正常 `systemctl stop` 即可。

---

## 8. 运行模式

| 模式 | 关键参数 | 说明 |
|---|---|---|
| 审计（默认） | （无） | 只记录/告警，响应 dry-run |
| 强制 | `--enforce` | kill/quarantine/nft 真正执行 |
| 自保护 | `--self-protect` | 精确拦截指向 Agent 的信号/内存操作 + 反击杀 |
| BPF 对象守卫 | `--bpf-guard` | 按 id 拦截对 Agent 自有 BPF 对象的破坏性操作 |
| LSM 强化 | `--lsm` | 内核权威 backstop（需内核 `lsm=…bpf`），Cover `tkill` 等 |
| 严格模块 | `--strict-modules` | 拦截非 Agent 的 `init_module/finit_module`（仅适用于运行时不加载模块的主机） |
| 文件同步拦截 | `--datapath-socket PATH` + `edr-datapath` | fanotify `FAN_OPEN_PERM` 同步决策 |
| 上报中心 | `--center-url … --center-secret-file /etc/edr/center.secret` | 事件入中心 + 动作轮询 |
| rootkit 扫描 | `--rootkit-scan` / `--rootkit-interval` / `--rootkit-min-lifetime` | 隐藏进程/模块 + syscall 完整性；`--rootkit-connections` 可选 |
| 告警 | `--notify-config /etc/edr/notify.json` | webhook/syslog/email |

**Agent 主要参数**（完整见 `edr-agent -h`）：

```
--policy --pubkey --once --bpf --self-protect --bpf-guard --lsm --strict-modules
--self-check-dir --datapath-socket --watch --enforce --quarantine-dir
--nft-enabled --nft-table --nft-chain
--event-path --anchor-file --anchor-url --anchor-every --anchor-secret-file
--audit-key-file --socket --allowed-uids --admin-key
--center-url --center-secret --center-secret-file --host
--masquerade-scan --masquerade-interval --rootkit-scan --rootkit-interval
--rootkit-min-lifetime --rootkit-connections --proc-root --sys-root
--notify-config --run-for
```

---

## 9. 使用 CLI

```bash
EDR=/opt/edr/bin
SOCK=/run/edr/agent.sock

$EDR/edrctl version
sudo $EDR/edrctl --socket $SOCK status
sudo $EDR/edrctl --socket $SOCK events query --limit 20
sudo $EDR/edrctl --socket $SOCK events query --rule HOST-REVSHELL-DEVTCP
```

### 9.1 管理员令牌（一次性）

令牌绑定动作，**一次一用**（重复使用返回 403）：

```bash
T() { sudo $EDR/edrctl admin token enforce-toggle --key-file /etc/edr/admin.key; }
sudo $EDR/edrctl --socket $SOCK response kill --pid 1234 --token "$(T)"

# 令牌也可写文件，避免出现在 /proc/<pid>/cmdline：
sudo $EDR/edrctl admin token enforce-toggle --key-file /etc/edr/admin.key > /tmp/tok
sudo $EDR/edrctl --socket $SOCK response kill --pid 1234 --token-file /tmp/tok
```

动作：`shutdown` / `restart` / `policy-reload` / `enforce-toggle`（响应类动作使用 `enforce-toggle`）。

### 9.2 策略

```bash
$EDR/edrctl policy validate /etc/edr/policy.json
$EDR/edrctl policy keygen /etc/edr/policy.key /etc/edr/policy.pub
$EDR/edrctl policy sign /etc/edr/policy.key /etc/edr/policy.json
sudo $EDR/edrctl --socket $SOCK policy reload --token "$(T)"   # 或 --token-file
```

> 生产建议：Agent 用 `--pubkey /etc/edr/policy.pub` 启动，只接受已签名策略。

### 9.3 审计校验

```bash
# 本地（HMAC + 文件锚定）
$EDR/edrctl events verify /var/lib/edr/events.jsonl \
  --key-file /etc/edr/audit.key --anchor-file /var/lib/edr/anchor.json

# 远程锚定（中心）
$EDR/edrctl events verify /var/lib/edr/events.jsonl \
  --key-file /etc/edr/audit.key \
  --anchor-url http://CENTER:7080/v0/center/anchor \
  --secret-file /etc/edr/center.secret
```

### 9.4 运营中心

```bash
SEC=$(sudo cat /etc/edr/center.secret)
U=http://127.0.0.1:7080
sudo $EDR/edrctl center hosts        --url $U --secret-file /etc/edr/center.secret
sudo $EDR/edrctl center events       --url $U --secret-file /etc/edr/center.secret --limit 20
sudo $EDR/edrctl center correlations --url $U --secret-file /etc/edr/center.secret
sudo $EDR/edrctl center cases create --url $U --secret-file /etc/edr/center.secret --title demo --severity high
sudo $EDR/edrctl center cases list   --url $U --secret-file /etc/edr/center.secret
sudo $EDR/edrctl center report       --url $U --secret-file /etc/edr/center.secret
sudo $EDR/edrctl center export       --url $U --secret-file /etc/edr/center.secret --format cef --limit 5
```

> `--secret` 仍可用，但推荐 `--secret-file`（避免密钥出现在命令行）。

---

## 10. 策略

策略文件为 JSON（`schema_version: v2.0`），包含 `rules` 与 `sequences`。

```json
{
  "schema_version": "v2.0",
  "rules": [
    {
      "id": "HOST-EXAMPLE",
      "description": "example",
      "category": "process",
      "severity": "high",
      "decision": "alert",
      "action": "log",
      "priority": 50,
      "when": {
        "op": "and",
        "args": [
          { "op": "eq", "field": "process_name", "value": "bash" },
          { "op": "contains", "field": "cmdline", "value": "/dev/tcp/" }
        ]
      }
    }
  ],
  "sequences": [
    {
      "id": "HOST-SEQ-EXAMPLE",
      "category": "process",
      "severity": "high",
      "decision": "block",
      "action": "kill",
      "within_sec": 30,
      "same_pid": false,
      "stages": [
        { "op": "in", "field": "process_name", "value": "curl,wget" },
        { "op": "in", "field": "process_name", "value": "bash,sh,dash" }
      ]
    }
  ]
}
```

常用字段：`process_name`、`process_path`、`cmdline`、`environ`、`file_path`、`file_op`、
`remote_addr`、`privtype`、`event_kind`、`rootkit_type`。
`category`：`process` / `file` / `network` / `rootkit`。
`decision`：`alert` / `block`；`action`：`log` / `kill` / `kill_tree` / `quarantine` /
`fix_permissions` / `process_suspend` / `nft_block` / `network_isolate` / `network_restore`。

基线规则覆盖：反弹 Shell、临时目录执行、LD_PRELOAD、提权（setuid/setgid/capset）、
进程伪装、SUID 设置、setcap、nsenter、反取证、模块/BPF 操作、敏感文件读写、SSH
authorized_keys、cron 持久化、TMP 投放、io_uring 文件改动、rootkit 跨源异常、自保护篡改。

---

## 11. 运营中心

`edr-center` 是独立的中心服务（生产应部署在独立节点；Lab 可与 Agent 同机）：

```bash
sudo /opt/edr/bin/edr-center \
  --listen 127.0.0.1:7080 \
  --data-dir /var/lib/edr-center \
  --shared-secret-file /etc/edr/center.secret
```

- **接入**：Agent 通过 `--center-url http://CENTER:7080/v0/center/ingest`
  与 `--center-secret-file` 上报；请求 HMAC 签名（含 query），响应体签名。
- **存储**：按主机 `hosts/<host>/events.jsonl`（追加）；链连续性 `gaps`。
- **远程锚点**：`/v0/center/anchor`，**单调**（拒绝下调），可被 Agent 用作
  `--anchor-url`（防本地改写锚定）。
- **闭环**：查询 → 关联/ATT&CK → 案件 → 处置编排（封闭枚举 + 审批 + Agent 轮询执行）→
  报告/CEF/LEEF。
- **信任模型**：当前为共享密钥；生产建议叠加 **mTLS + 每主机凭据**（见
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)）。

Agent 上报示例：

```bash
sudo /opt/edr/bin/edr-agent --bpf --policy /etc/edr/policy.json \
  --event-path /var/lib/edr/events.jsonl --anchor-file /var/lib/edr/anchor.json \
  --audit-key-file /etc/edr/audit.key \
  --socket /run/edr/agent.sock --admin-key /etc/edr/admin.key \
  --center-url http://127.0.0.1:7080/v0/center/ingest \
  --center-secret-file /etc/edr/center.secret
```

---

## 12. 审计与完整性

- **哈希链**：每条事件 `chain.seq/prev_hash/hash`；可选 **HMAC**（`--audit-key-file`）。
- **锚定**：`--anchor-file`（本地镜像）或 `--anchor-url`（中心远程锚点）。
- **校验语义**：
  - 带 HMAC 的链，未提供 key → `hmac_unverified`（`ok=false`）；
  - 错误 key → `hmac_mismatch`；
  - 篡改/删除 → `hash_mismatch` / `seq_gap`；
  - 截断 → `anchor_truncation`；
  - 锚定文件损坏/不可读 → **拒绝启动**（fail-closed），不会静默新建链。
- **跨重启**：始终传 `--anchor-file`/`--anchor-url`，链从锚定续接；否则 `events verify`
  会因 seq 重置报 `seq_gap`。

> HMAC key 若放在主机上，root 可读；要对抗 root 需将密钥置于 **TPM/安全元件**或外部签名服务。
> 远程锚点可发现本地锚定改写，建议生产启用。

---

## 13. 自保护与 rootkit 检测

### 自保护

- **信号/内存**：只拦截目标 == Agent 的 `kill/tgkill/rt_sigqueueinfo/pidfd_send_signal/
  process_vm_readv/writev/ptrace`，并反击杀；精确、不误伤其他进程。
- **BPF 对象守卫**：按 `edr_own_ids` 判定，仅拦对**自有对象**的
  map update/delete/freeze、prog/link detach、PROG_ATTACH/LINK_CREATE/LINK_UPDATE。
- **可选 LSM**（`--lsm`）：`lsm/task_kill` + `lsm/ptrace_access_check`，覆盖 kprobe
  未挂的路径（如 `tkill`、`/proc/pid/mem`）。需内核 `lsm=…bpf`。
  启动顺序保证：**先挂 LSM，再武装**，且武装时先写 LSM 配置，无半保护窗口。
- **严格模块**（`--strict-modules`）：拦截非 Agent 的模块加载（对抗 root+LKM）；
  仅用于运行时不加载模块的主机。
- **完整性哨兵**：心跳、`agent_pid`、二进制哈希、安装目录、datapath 存活 → 失败发 SOS。
- **丢事件告警**：pipeline/BPF 出现丢弃即发高危事件（防洪水致盲）。

### rootkit

- 隐藏进程（探测见过的 PID vs `/proc`）、隐藏模块（`/sys/module` vs `/proc/modules`）、
  syscall 完整性（`/proc/kallsyms` `_text.._etext`）。
- 隐藏连接为可选（`--rootkit-connections`，`/proc/net/tcp` 时序在繁忙主机易误报）。
- io_uring 的 unlink/rename 通过 `vfs_unlink`/`vfs_rename` 探针覆盖（`HOST-IOURING-FILEOP`）。

### 启用 BPF LSM（一次性）

```bash
# 确认 CONFIG_BPF_LSM=y
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"/' /etc/default/grub
sudo update-grub && sudo reboot
cat /sys/kernel/security/lsm   # 应含 bpf
```

---

## 14. 告警渠道

`/etc/edr/notify.json`（默认 `{}` = 关闭；示例见 `configs/notify.example.json`）：

```json
{
  "queue_size": 1024,
  "webhooks": [
    { "url": "https://hooks.example/edr", "format": "generic", "min_severity": "high",
      "headers": { "X-EDR-Channel": "soc" }, "timeout_sec": 5 }
  ],
  "syslog": { "enabled": false, "network": "udp", "address": "10.0.0.10:514",
              "facility": 3, "min_severity": "medium" },
  "email": { "enabled": false, "host": "smtp.example", "port": 587,
             "username": "edr@example", "password": "$EDR_SMTP_PASSWORD",
             "from": "edr@example", "to": ["soc@example"], "use_tls": true,
             "min_severity": "critical" }
}
```

- 格式：`generic` / `dingtalk` / `wechat_work` / `feishu`。
- 每个渠道独立 `min_severity`；异步有界队列，满队列丢弃并计数（不阻塞检测）。
- 自保护 SOS 会立即投递。

---

## 15. 测试与质量

```bash
make gate          # 必过门禁（离线、无需 root）
make capability    # 能力矩阵（48/48）
make test-race     # 竞态
```

**真机功能测试**（需已安装 lab，root；脚本在 `test/functional/`）：

```bash
scp test/functional/{ft1.sh,ft2.sh,resource.sh} user@HOST:/tmp/
ssh user@HOST 'sudo bash /tmp/ft1.sh'      # 检测/强制/自保护/审计/稳定性
ssh user@HOST 'sudo bash /tmp/ft2.sh'      # 运营中心/告警/rootkit
ssh user@HOST 'sudo bash /tmp/resource.sh' # 稳态 CPU/RSS/drops
```

`ft1` 覆盖 13+ 条规则、审计与篡改、6 类响应、控制面鉴权、自保护（信号/pidfd/BPF map/ATTACH/LSM/哨兵）；
`ft2` 覆盖中心全链路、告警过滤、rootkit。详见 `test/functional/README.md`。

---

## 16. 安全模型与已知边界

完整攻击矩阵见 [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)。要点：

- **本地 root + 恶意内核模块**可压制任何本地 EDR：`--strict-modules`、模块签名、安全启动、
  kernel lockdown 是必要的外部边界。
- **审计 HMAC 密钥在主机上** → root 可读；对抗 root 需 TPM/外部密钥；远程锚点可发现截断/改写。
- **`/proc/pid/mem`、`process_madvise`** 依赖 LSM 层拦截（纯 kprobe 档不覆盖）。
- **io_uring** 的 unlink/rename 已覆盖；mkdir/symlink/link 尚未覆盖。
- **路径型 fanotify** 可被挂载别名影响；关键文件建议按 inode。
- **中心**当前共享密钥 + 明文 HTTP（无 mTLS）；生产建议 mTLS + 每主机凭据 + 远端锚定 + 失联告警。
- **模块加载默认仅告警**（通用主机定位），可用 `--strict-modules` 升级。

---

## 17. 排错

| 现象 | 处理 |
|---|---|
| `control socket: bind: no such file or directory` | `/run/edr` 丢失（重启后）；`sudo mkdir -p /run/edr && sudo chmod 750 /run/edr`。系统已装 tmpfiles 自动重建 |
| `systemctl stop edr-agent` 卡住 | 开了 `--self-protect`；用受控 shutdown（§7.4） |
| 响应动作 403 | admin token 已用过（一次一用）；重新 `edrctl admin token …` |
| `events verify` 报 `seq_gap` | 未传锚定或每次启动新链；始终传 `--anchor-file`/`--anchor-url` |
| `hmac_unverified` | 链带 HMAC 但未传 `--key-file` |
| 中心锚点首次 404 | 正常（该主机尚无锚点）；产生事件并等待 `--anchor-every` 后重试 |
| `--lsm` 提示未启用 | 内核未开启 BPF LSM（§13） |
| `--strict-modules` 影响运维 | 仅用于运行时不加载模块的主机；否则改回默认 |

---

## 18. 文档索引

- [`docs/OVERVIEW.md`](docs/OVERVIEW.md) — 项目总览（架构/模块/里程碑/取舍）
- [`docs/MODULES.md`](docs/MODULES.md) — 模块、探针、里程碑状态
- [`docs/DEPLOY-LAB.md`](docs/DEPLOY-LAB.md) — 部署与人工测试剧本（A–O）
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — 红队视角攻击矩阵与残余风险
- [`docs/OPS-CENTER.md`](docs/OPS-CENTER.md) — 运营中心设计
- [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) — 目标环境与 BPF LSM 结论
- [`docs/M0-INTERFACES.md`](docs/M0-INTERFACES.md) — M0 接口契约与 Rust IPC 协议
- [`docs/PLAN.md`](docs/PLAN.md) — 迁移规划与目标架构
- [`docs/capability-matrix.md`](docs/capability-matrix.md) — 由测试生成的能力矩阵
- [`test/functional/README.md`](test/functional/README.md) — 真机功能测试说明

---

## 19. 开发约定

- **不做"文档宣称 ≠ 运行时"**：新增能力必须有测试，并更新 `make capability`。
- **精确强制**：新响应/自保护逻辑必须限定目标，禁止全局拦截。
- **fail-safe 方向明确**：遥测可 fail-open（有界丢弃并计数）；强制路径不得把 dry-run 计为阻断。
- **策略/字段变更**：同步 `internal/policy`、`internal/detect`、`configs/*.json` 与测试。
- **BPF 变更**：改 `probes/*.bpf.c` 后运行 `make bpf-gen`，并更新 `decode.go` 偏移与
  `_Static_assert`。
- **提交前**：`make gate` 全绿；如改能力，`make capability` 并提交矩阵。

---

**License:** MIT © 2026 cheaterida
