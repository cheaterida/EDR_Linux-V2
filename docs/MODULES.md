# EDR v2 功能模块规划

> 状态图例：✅ 已实现 · 🚧 进行中 · ⬜ 规划中
> 里程碑：M0 骨架 → M1 采集 → M2 检测 → M3 响应 → M4 审计 → M5 自保护 → M6 控制面 → M7 HA/分发 → M8 运营中心

---

## 1. 总体分层

```
┌──────────────────────────────────────────────────────────────────────┐
│  M8 审计运营中心 (center)                                            │
│  ingest · store · 关联分析 · 案件 · 报告 · 处置编排 · UI/CLI          │
└───────────────────────────────▲──────────────────────────────────────┘
                                │ mTLS / 签名事件 + anchor
┌───────────────────────────────┴──────────────────────────────────────┐
│  单机 Agent (M0–M7)                                                   │
│                                                                        │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────────┐  │
│  │ collect   │→ │ pipeline  │→ │ detect    │→ │ respond / protect │  │
│  │ (M1)      │  │ (M0 ✅)   │  │ (M0 ✅)   │  │ (M3/M5)           │  │
│  └─────▲─────┘  └─────┬─────┘  └───────────┘  └─────────┬─────────┘  │
│        │              │                                  │            │
│  ┌─────┴─────┐  ┌─────▼─────┐  ┌───────────┐  ┌─────────▼─────────┐  │
│  │ bpf/procfs│  │  policy   │  │  audit    │  │ control (M6)      │  │
│  │ fanotify  │  │  (M0 ✅)  │  │  (M0 ✅)  │  │ notify/metrics    │  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 2. Agent 侧模块清单

| 模块 | 职责 | 里程碑 | 状态 |
|------|------|:---:|:---:|
| `internal/event` | 版本化事件模型（单一事实源） | M0 | ✅ |
| `internal/pipeline` | 阶段化管线 + 有界背压 + 高优通道 + 丢事件计数 | M0 | ✅ |
| `internal/policy` | 条件树规则模型 + 序列规则 + 校验 + Ed25519 签名/热重载 | M0/M2 | ✅ |
| `internal/detect` | 事件类型倒排索引 + 条件树求值 + allow 覆盖 + 序列引擎 | M0/M2 | ✅ |
| `internal/audit` | 哈希链 + HMAC + seq 连续 + 拒绝降级 + anchor（文件/HTTP）+ 轮转校验 | M0/M4 | ✅ 真机验证 |
| `internal/capmatrix` | 能力矩阵（由测试生成） | M0 | ✅ |
| `internal/bpf` | CO-RE 探针 + bpf2go + loader（cilium/ebpf） | M1 | ✅ exec/fork/exit/connect/unlink/rename，真机验证 |
| `internal/collect/procfs` | /proc 快照 + 富化（cmdline/environ/maps/cap/ns/cgroup） | M1 | ✅ 按需富化，真机验证 |
| `internal/collect/ringbuf` | BPF 事件解码 + 背压 | M1 | ✅ 已并入 `internal/bpf` |
| `internal/collect/inotify` | 文件变更观测（fallback） | M1 | ✅ 递归 watch + 新目录继承 + 背压计数 |
| `internal/platform` | procutil / pidfd / cgroup / namespace / caps | M1/M3 | 🚧 部分在 `internal/collect` |
| `internal/respond` | kill(pidfd 目标校验)/kill_tree/quarantine(+恢复)/fix_permissions/suspend + nft_block/network_isolate/network_restore（参数化、dry-run） | M3 | ✅ 真机验证 |
| `internal/respond/datapath` | Rust 小边界客户端（IPC） | M3 | ✅ 客户端 + 协议 + 策略编译 |
| `internal/protect` | own_bpf_objs 注册 + 精确信号/内存拦截 + **BPF 对象守卫（id 精确）** + 心跳/agent_pid/**二进制哈希/安装目录**哨兵 + SOS | M5 | ✅ 真机验证 |
| `internal/integrity` | 进程伪装检测（kworker 等内核线程伪装）+ SOS（由 protect/agent 实现） | M5 | ✅ 真机验证 |
| `internal/rootkit` | 跨源一致性检测：隐藏进程（探测见到的 PID vs `/proc`）、隐藏模块（`/sys/module` vs `/proc/modules`）、kallsyms 系统调用完整性；隐藏连接为可选（`--rootkit-connections`）。产出 `KindRootkit` 事件交策略引擎 | P1 | ✅ 真机验证（无误报 + 端到端正向） |
| `internal/control` | HTTP over Unix socket + SO_PEERCRED 白名单 + admin token（nonce 防重放）+ /v0/status|events|policy|reload|shutdown | M6 | ✅ 真机验证 |
| `internal/adminauth` | HMAC bearer token 签发/验证 + 防重放 | M6 | ✅ |
| `internal/notify` | webhook（generic/dingtalk/wechat/feishu）+ 远程 syslog(RFC5424) + email；严重度过滤 + 异步背压 | M6 | ✅ 测试验证 |
| `internal/metrics` | Prometheus 指标 | M6 | ⬜ |
| `internal/liveness` | 心跳文件 + 健康状态机（healthy/suspect/down） | M7 | ✅ |
| `internal/lease` | 单写者文件租约（TTL + 代际）防脑裂 | M7 | ✅ 真机验证 |
| `internal/requestauth` | HA HTTP HMAC 签名 + 防重放 | M7 | ✅ |
| `internal/supervisor` | 仲裁（心跳→重启意图 + 冷却） | M7 | ✅ |
| `cmd/edr-orchestrator` | HA 故障切换循环（本地 + supervisor 仲裁） | M7 | ✅ 真机验证 |
| `datapath/`（Rust） | fanotify 同步决策 + 响应原语 + guardian | M1/M3/M5 | ✅ fanotify 同步 deny + pidfd kill，真机验证 |

## 3. BPF 探针规划（CO-RE）

| 探针 | 事件 | Hook | 用途 | 里程碑 |
|------|------|------|------|:---:|
| exec | `KindExec` | `sched_process_exec` | 执行 + exe + **内核态 argv（cmdline）** | M1 ✅ |
| connect | `KindConnect` | `inet_sock_set_state` | 外联（含 ring0 黑名单可选） | M1 |
| fork/exit | `KindFork/Exit` | `sched_process_fork/exit` | 进程树 + 缓存清理 | M1 |
| file_mon | `KindFileOp` | `unlink/unlinkat/renameat` | 删除/改名 | M1 |
| selfprotect | `KindSelfProtect` | `kprobe __x64_sys_{kill,tgkill,rt_sigqueueinfo,pidfd_send_signal,ptrace,process_vm_readv/writev}` + getpid 心跳 | 自保护（**目标校验**） | M5 ✅ |
| bpf_guard | `KindSelfProtect` | `kprobe __x64_sys_bpf` | **只拦对 agent 自身 BPF 对象的 map update/delete/freeze、prog/link detach，以及 PROG_ATTACH / LINK_CREATE / LINK_UPDATE（按 `edr_own_ids` id 精确）** | M5 ✅（真机 map 篡改 + `bpftool cgroup attach` 验证） |
| lsm（可选） | — | `lsm/task_kill`、`lsm/ptrace_access_check` | **内核权威 backstop**：覆盖 kprobe 未挂的路径（如 `tkill`）；`--lsm` 且内核 `lsm=…bpf` 时加载，失败不影响 kprobe 主路径 | M5 ✅（真机 `tkill` 验证） |
| rootkit（用户态周期） | `KindRootkit` | 由 `internal/rootkit` 每 `--rootkit-interval` 扫描 | 跨源一致性：隐藏进程/模块/连接 + syscall 完整性；`learnStage` 先学习 exec/fork/exit/connect | P1 ✅ |
| vfs/io_uring | `KindFileOp`（`vfs_unlink`/`vfs_rename`/`vfs_rename_to`） | `kprobe vfs_unlink`、`kprobe vfs_rename` + `kprobe __x64_sys_io_uring_enter`（任务标记 map） | 覆盖 io_uring 文件改动（绕过 syscall 探针）；文件名取 dentry basename | P1+ ✅（真机 io_uring unlink 验证） |
| ptrace_enh | `KindPtrace` | `kprobe __x64_sys_ptrace` | 反调试 | M5 |
| ldpreload | `KindLDPreload` | `sys_enter_execve` | 注入 | M5 |
| instrument | `KindInstrument` | `kprobe __x64_sys_mmap` | Frida 等插桩 | M5 |
| privesc | `KindPrivesc` | `sys_enter_{setuid,setgid,capset}` | 提权 | M1 ✅ |
| module | `KindModuleLoad/Unload` | `sys_enter_{init,finit,delete}_module` | LKM rootkit | M1 ✅ |
| bpfop | `KindBPFOp` | `sys_enter_bpf` | eBPF rootkit | M1 ✅ |

**强制层（运行时可探测，见 `ENVIRONMENT.md`）**

- 主路径：kprobe override（kill/ptrace/pidfd/bpf/module）
- 文件：fanotify `FAN_OPEN_PERM`
- 网络：nftables（用户态）
- 增强：BPF LSM（需 GRUB 开启 `bpf`）— 探测到才启用，缺失不静默

## 4. Rust `datapath` 小边界

| 组件 | 职责 |
|------|------|
| `fanotify.rs` | FAN_OPEN_PERM 同步决策（本地匹配 Go 下发的决策表） |
| `policy.rs` | 决策表 + 本地匹配 |
| `action.rs` | pidfd kill / quarantine / nft |
| `guardian.rs` | 心跳与自愈 |
| `ipc.rs` | 版本化帧协议（HELLO/POLICY_SNAPSHOT/EVENT/ACTION_REQ/ACTION_RESULT/HEARTBEAT） |

## 5. 运营中心侧模块（M8，详见 `OPS-CENTER.md`）

| 模块 | 职责 |
|------|------|
| `center/ingest` | 认证接入（HMAC）+ 去重 + 落库 + 链连续性校验 | M8 | ✅ |
| `center/store` | 按主机追加式事件存储 + 主机状态 | M8 | ✅ |
| `center/correlate` | 跨主机关联 + ATT&CK 映射 | M8.1 | ✅ 真机验证 |
| `center/cases` | 案件/时间线/处置结论 | M8.2 | ✅ 真机验证 |
| `center/orchestrate` | 下发处置（闭环枚举 + 审批 + 结果回传 + 审计） | M8.3 | ✅ 真机验证 |
| `center/report` | 报告 / SIEM 导出（CEF/LEEF） | M8.4 | ✅ 真机验证 |
| `center/trust` | anchor 汇聚与跨主机链校验 | M8.1 | 🚧 连续性已实现 |
| `center/ui` | CLI（edrctl center）/ 后续 Web | M8 | 🚧 CLI 已实现 |
---

## 6. 依赖关系（关键顺序）

```
event ─┬─ pipeline ─── detect ─── respond ── datapath(Rust)
       │      │
       │      └─ audit
       ├─ policy
       └─ collect(bpf/procfs/fanotify) → pipeline
                                   ↓
                           protect(M5) → control(M6) → ha(M7) → center(M8)
```

## 7. 里程碑交付与验收

| 里程碑 | 交付 | 验收 |
|:---:|------|------|
| M0 | 骨架 + 门禁 + 能力矩阵 | ✅ `make gate` 绿；矩阵 8/8 |
| M1 | CO-RE 采集 + procfs 富化 + 管线接入 | 🚧 CO-RE 采集已实机验证；procfs 富化/更多探针待续 |
| M2 | 规则 DSL + 序列规则 + 策略签名热重载 | ✅ 真机验证：序列命中；篡改签名被拒 |
| M3 | 响应动作（kill/quarantine/nft/隔离/恢复） | ✅ 真机验证：kill、quarantine、nft_block、rollback、restore |
| M4 | 审计强化（anchor 接线/截断/降级） | ✅ 真机验证：篡改/降级/截断/一致 四例 |
| M5 | 自保护（own_bpf_objs/kprobe 精确拦截/周期心跳/哨兵接线） | ✅ 真机验证：root kill -9 被阻断 + 反击杀；自保护事件入链 |
| M6 | 控制面认证 + CLI | ✅ 真机验证：peercred 403 / status·events·policy / token reload / 重放拒绝 |
| M7 | HA split A/B + supervisor | ✅ 真机验证：租约防脑裂、恰好一次重启、恢复释放 |
| M8 | 运营中心 | ✅ M8.0 接入/存储/查询；M8.1 关联+ATT&CK；M8.2 案件；M8.3 处置编排；M8.4 报告/CEF/LEEF |
