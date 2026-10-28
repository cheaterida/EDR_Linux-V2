# EDR v2 项目总览

> 状态：M0–M8.2 全部完成，且在每个里程碑均于真机（`192.168.214.144`, Ubuntu 24.04 / kernel 6.17）验证。
> 本文是项目的单一入口：架构、模块、里程碑、验证证据、设计取舍与剩余工作。

---

## 1. 项目定位

面向 Linux 的单机 + 中心化主机入侵检测与响应系统（EDR），是
`~/EDR-Linux-master`（v0.9.1）的**迁移重构**。目标：

- 内核优先采集（CO-RE eBPF）+ 用户态复杂分析
- 检测 → 响应 → 审计 → 自保护 → 控制面 → HA → 运营中心 的完整闭环
- 以**可验证性**为第一约束：能力由测试生成，杜绝"文档宣称 ≠ 运行时"（旧项目核心问题）

## 2. 架构总览

```
┌─────────────────────────── 运营中心 (edr-center) ───────────────────────────┐
│  认证接入(HMAC) → 按主机存储 → 链连续性校验 → 关联(ATT&CK) → 案件 → CLI       │
└───────────────────────────────▲─────────────────────────────────────────────┘
                                │ 签名批量上报 (center forwarder)
┌───────────────────────────────┴─────────────────── 单机 Agent ──────────────┐
│  事件管线:  host → enrich(/proc) → detect(规则+序列) → respond → audit(哈希链)  │
│                                                                              │
│  collect: CO-RE eBPF · procfs · inotify        datapath(Rust): fanotify/pidfd │
│  protect: own BPF 对象 + 精确拦截 + 心跳哨兵 + SOS                              │
│  control: Unix socket API (SO_PEERCRED + admin token)                         │
│  audit:   SHA-256 链 + HMAC + 文件/HTTP anchor + 轮转校验                       │
└───────────────────────────────▲──────────────────────────────────────────────┘
                                │ 心跳 + 租约 (HA)
                         edr-orchestrator (split A/B, supervisor 仲裁)
```

**语言边界（Go/Rust 混合）**：Go 为控制面/大脑（检测、策略、审计、控制面、HA、中心）；
Rust 为数据面（fanotify 同步决策、pidfd 响应原语）；C 为内核态探针（CO-RE）。
Rust 与 Go 通过版本化 Unix socket 帧协议通信。

## 3. 代码规模

| 项 | 值 |
|---|---|
| Go 包 | 19 个 `internal/*` + 5 个 `cmd/*` + 1 个验收测试包 |
| Go 文件 / 行数 | 65 个 / ~9,883 行 |
| Rust | 5 个源文件（`datapath/`） |
| BPF | `probes.bpf.c` + `common.h`（CO-RE）+ `bpf2go` 生成绑定 |
| 能力矩阵 | **30 / 30**（由 `test/capability` 生成） |

可执行入口：`edr-agent`（单机核心）、`edr-center`（运营中心）、`edr-orchestrator`（HA）、
`edr-preflight`（只读预检）、`edrctl`（CLI）。

## 4. 模块清单

| 模块 | 职责 |
|---|---|
| `internal/event` | 版本化事件模型（typed 子结构 + host 归因 + 命名空间） |
| `internal/pipeline` | 有界背压管线 + 高优通道 + 丢事件计数 |
| `internal/policy` | 条件树规则 + 序列规则 + Ed25519 签名 + 热重载 |
| `internal/detect` | 事件类型倒排索引 + 条件树求值 + 序列引擎 + 原子 Holder |
| `internal/bpf` | CO-RE 探针 + `bpf2go` 绑定 + 加载器 + 解码 + 自有对象注册 |
| `internal/collect` | `/proc` 按需富化 + inotify fallback |
| `internal/datapath` | Rust 守护客户端（协议/策略编译/fanotify 事件） |
| `internal/respond` | kill(pidfd 目标校验)/kill_tree/quarantine/fix_permissions/suspend |
| `internal/audit` | SHA-256 链 + HMAC + seq 连续 + 拒绝降级 + 文件/HTTP anchor |
| `internal/protect` | 自保护：信号/内存拦截 + BPF 对象守卫（id 精确）+ 哨兵（心跳/agent_pid/二进制哈希/安装目录） |
| `internal/rootkit` | 跨源一致性：隐藏进程/模块 + syscall 完整性（kallsyms）；隐藏连接可选 |
| `internal/control` | Unix socket API + SO_PEERCRED + admin token |
| `internal/adminauth` | HMAC bearer token（防重放） |
| `internal/center` | 运营中心：存储/接入/连续性/查询/关联/ATT&CK/案件 |
| `internal/liveness` / `internal/lease` | 心跳状态机 + 单写者租约（防脑裂） |
| `internal/requestauth` / `internal/supervisor` | HA 请求签名 + 仲裁重启意图 |
| `internal/capmatrix` | 能力矩阵生成 |
| `datapath/`（Rust） | fanotify 同步决策 + pidfd kill + IPC |

## 5. 里程碑与真机验证证据

| 里程碑 | 交付 | 验证证据（真机） |
|---|---|---|
| M0 | 骨架 + 门禁 + 能力矩阵 | `make gate` 全绿 |
| M1 | CO-RE 采集 + procfs 富化 + inotify + fanotify/Rust datapath | exec/unlink 入链；cmdline 富化命中；`cat` 被 `FAN_DENY` |
| M2 | 序列规则 + 签名热重载 | `sleep→id` 序列命中；篡改签名被拒 |
| M3 | 响应（pidfd 目标校验 / quarantine） | victim `killed via pidfd`；文件 `quarantined` |
| M4 | 审计强化（VerifyFile/anchor/CLI） | 篡改=hash_mismatch；降级=missing_integrity；截断=anchor_truncation |
| M5 | 自保护（own 对象 + 精确拦截 + BPF 对象守卫 + pidfd + 可选 LSM + 哨兵/SOS） | root `kill -9`/`pidfd_send_signal` 被阻断 + 反击杀；`bpftool` 改 agent_pid map 被 -EPERM（无关 map 放行）；LSM 下 `tkill` 被拦；`kind:5` 入链 |
| M6 | 控制面（SO_PEERCRED + admin token） | 非 root→403；token reload ok；重放→403 |
| M7 | HA（liveness/lease/supervisor） | 双实例仅租约持有者重启（防脑裂），恢复释放 |
| M8.0 | 运营中心接入/存储/查询 | 按主机聚合 `events/gaps`；错误密钥 403 |
| M8.1 | 关联 + ATT&CK | `host_chain` 带 tactics/techniques |
| M8.2 | 案件管理 | create→investigating→true_positive，时间线持久化 |
| M8.3 | 中心→agent 处置编排 | 审批后 agent 轮询执行 kill（`killed via pidfd`）并回传；任意命令被拒 |

## 6. 关键设计取舍

1. **可验证性优先**：`docs/capability-matrix.md` 由 `test/capability` 生成；CI 会因矩阵过期而失败。
2. **精确强制**：自保护只拦截**目标 == agent** 的信号/内存操作，BPF 对象以 `own_bpf_objs` 识别——修正旧项目"拦截所有信号/所有 bpf 操作"的自伤。
3. **fail-safe 方向明确**：遥测可 fail-open（背压丢弃并计数）；强制路径显式返回 `Enforced`，绝不把 dry-run 计为阻断。
4. **锚定语义正确**：链头锚定外部存储 + 跨轮转校验 + 拒绝降级 + 从锚定续接，截断可检测。
5. **中心只做可信汇聚，不做任意命令下发**：命令为封闭枚举（处置动作）。
6. **CO-RE + 纯 Go 加载器**：消除旧项目 `vmlinux.h` 内核强绑定。

## 7. 工程与质量

| 项 | 说明 |
|---|---|
| 门禁 | `make gate` = gofmt + vet + test + build |
| 能力 | `make capability` 生成能力矩阵（当前 30/30） |
| BPF | `make vmlinux` / `make bpf-gen`（需 clang + bpftool + BTF） |
| Rust | `make datapath-build` |
| 预检 | `make preflight` → `edr-preflight`（只读主机能力探测） |
| CI | Go 全量测试 + 能力矩阵陈旧检查；Rust `cargo build/test` |

## 8. 已知限制与剩余工作

**限制**
- BPF LSM 为**可选强化**：默认未在启动参数启用（提供 GRUB 指引）；启用后 `--lsm` 挂载 `lsm/task_kill` + `lsm/ptrace_access_check`，作为内核权威 backstop。已在测试机开启并验证：kprobe 未覆盖的 `tkill` 路径被 LSM 拦截（EPERM）。**无半保护窗口**：LSM 在武装前挂载，武装时先写 LSM 配置再写 kprobe 配置。内核不支持时优雅跳过，不影响主路径。
- 自保护信号覆盖 kill / tgkill / rt_sigqueueinfo / **pidfd_send_signal** / process_vm_readv/writev + ptrace；`tkill` 等未挂路径由 LSM 层覆盖。
- BPF 对象守卫已实现**目标级精确拦截**（按 `edr_own_ids` 判定，仅拦对 agent 自身对象的 bpf() 操作）：map update/delete/freeze、prog/link detach、**PROG_ATTACH / LINK_CREATE / LINK_UPDATE（attach/relink 族）**。模块加载按通用主机定位保持**仅告警**；`pidfd_send_signal` 已覆盖。
- 采集在"attach 未完成即开始活动"的短窗口下会偏少（时序，非缺陷）。
- 中心存储在单机文件/JSON；尚未接入 ClickHouse/Parquet 与 mTLS。

**剩余**
- 中心存储升级（ClickHouse/Parquet）、mTLS、指标暴露（Prometheus）
- 处置编排增强：多阶段剧本、自动建案与自动处置策略
- 采集 syscall 覆盖扩展（execveat/clone3/openat2/mount/namespace）

## 9. 快速开始

```bash
make gate                                   # 门禁
make capability                             # 生成能力矩阵
go run ./cmd/edr-agent --once --policy testdata/m1-demo.json

# 真机（root）：CO-RE 采集 + 自保护
sudo go run ./cmd/edr-agent --bpf --self-protect --policy testdata/m1-collect.json --run-for 10s

# Rust datapath（fanotify 同步拦截）
make datapath-build
sudo ./datapath/target/release/edr-datapath --socket /run/edr/datapath.sock --watch /tmp/edr-watch &
sudo go run ./cmd/edr-agent --bpf --datapath-socket /run/edr/datapath.sock --policy testdata/m1-datapath.json

# 运营中心
go run ./cmd/edr-center --listen 127.0.0.1:7080 --data-dir /tmp/edr-center-data --shared-secret S &
edrctl center cases list --url http://127.0.0.1:7080 --secret S
```

## 10. 文档索引

- `docs/PLAN.md` — 迁移规划与目标架构
- `docs/MODULES.md` — 模块/里程碑/探针清单
- `docs/OPS-CENTER.md` — 运营中心设计
- `docs/ENVIRONMENT.md` — 目标环境与 BPF LSM 结论
- `docs/capability-matrix.md` — 由测试生成的能力矩阵
- `docs/M0-INTERFACES.md` — M0 接口契约与 Rust IPC 协议
- `docs/OVERVIEW.md` — 本文
