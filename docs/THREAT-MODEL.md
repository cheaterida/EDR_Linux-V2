# 威胁模型（红队视角）

> 目标：从专业攻击者视角列出对本 EDR 的**绕过 / 破坏**手法，标注当前防护状态与残余风险。
> 假设：Agent 以 root 在**主机 PID/网络命名空间**运行；主要对手是**已获得 root 的攻击者**（或恶意运维）。
> 图例：**BLOCK** 自动拦截 ｜ **DETECT** 检测/告警 ｜ **PART** 部分/有条件 ｜ **GAP** 未覆盖。

## 1. 破坏 Agent 自身

| 手法 | 状态 | 说明 |
|---|---|---|
| `kill`/`tgkill`/`rt_sigqueueinfo`/`pidfd_send_signal` 杀 Agent | **BLOCK**（kprobe 精确拦截 + 反击杀） | 目标校验，仅拦截指向 Agent 的信号 |
| `ptrace` 附加 Agent | **BLOCK**（kprobe + LSM `ptrace_access_check`） | 拒绝并反击杀 |
| `process_vm_readv/writev` 读写 Agent 内存 | **BLOCK**（kprobe） | |
| **`/proc/<agent>/mem` 写入** | **BLOCK（仅启用 LSM 时）** | 走 `ptrace_may_access` → LSM `ptrace_access_check`；**纯 kprobe 档不覆盖** → 需启用 `--lsm` |
| **`process_madvise`/`process_mrelease` 干扰 Agent** | **BLOCK（仅启用 LSM 时）** | 同样走 ptrace 访问检查；纯 kprobe 档不覆盖 |
| `pidfd_getfd` 复制 Agent 的 fd（ringbuf/socket/BPF link） | **PART** | 复制 fd 后 `LINK_DETACH` 等破坏性操作仍按自有对象 id 拦截 |
| 篡改 Agent 的 BPF map/prog | **BLOCK**（bpf_guard，id 精确） | 覆盖 map update/delete/freeze、prog/link detach、PROG_ATTACH/LINK_CREATE/LINK_UPDATE |
| 篡改 LSM object 自有 map | **BLOCK** | 已注册进 `edr_own_ids`（本轮修复） |
| 杀/替换 Agent 二进制、删安装目录 | **DETECT**（哨兵：二进制哈希 / 安装目录 → SOS） | 运行期检测；跨重启需 IMA/安全启动 |
| 杀 `edr-datapath`（fanotify 数据面） | **DETECT**（哨兵探活 datapath socket → SOS，本轮新增） | 数据面死亡后文件同步拦截失效（fail-open） |
| 仅凭信号/命令强制重启绕过自保护 | **PART** | 受控停机走 API；`SIGTERM` 被拦；断电/硬重启不可防 |

## 2. 内核层压制（最致命）

| 手法 | 状态 | 说明 |
|---|---|---|
| 加载恶意 LKM（rootkit） | **BLOCK（需 `--strict-modules`）/ 默认 DETECT** | 默认仅告警；严格档拦截非 Agent 的 `init_module/finit_module`（本轮新增，真机验证） |
| LKM 在内核直接改 Agent map/prog（不经 syscall） | **GAP（若已加载 LKM）** | bpf_guard 只拦用户态 `bpf()`；内核态修改无法拦 → 必须不让 LKM 加载 |
| 卸载安全相关模块 | **DETECT** | `delete_module` 告警；未拦截（避免误伤运维） |
| 写 `/dev/mem`、`/proc/kcore` 篡改内核内存 | **GAP** | 依赖主机加固（`CONFIG_STRICT_DEVMEM`、lockdown、安全启动） |
| `kexec_load` 换内核 / 改 GRUB 关 LSM·EDR 自启 | **GAP** | 依赖安全启动 + GRUB 口令 + 度量启动；EDR 侧可加告警（后续） |
| 反射/BTF/`bpf_override_return` 竞争同 hook | **PART** | kprobe 共存，无法移除我方程序；顺序不保证 |

> 结论：**root + 恶意内核模块是当前最大的不可完全本地防御的路径**。要么用 `--strict-modules`，要么依赖安全启动/模块签名。这也是所有主机 EDR 的共性边界。

## 3. 检测规避

| 手法 | 状态 | 说明 |
|---|---|---|
| 伪装内核线程名（kworker 等） | **DETECT**（exe 判据） | 仅覆盖内核线程名；伪装成 `sshd/systemd` 等**未覆盖** |
| 跨源不一致（隐藏进程/模块/连接） | **DETECT**（rootkit 检测） | 依赖 `/proc`、`/sys`、`/proc/net/tcp`；**能同时伪造这些视图的 DKOM rootkit 可规避** |
| syscall 表 hook | **DETECT** | 依赖 `/proc/kallsyms`；rootkit 也可伪造 kallsyms |
| **洪水致盲**（大量事件导致 ringbuf/pipeline 丢事件） | **DETECT**（本轮新增 drops 告警） | 丢事件不再静默；但**丢事件期间的个别恶意事件仍会漏** |
| 通过 **io_uring** 发起 unlink/rename（绕过 `sys_enter_*`） | **DETECT**（`vfs_unlink`/`vfs_rename` 探针，识别 `iou-*` 线程与近期 `io_uring_enter` 的任务） | 生成 `file_op=vfs_unlink/vfs_rename*` 事件，命中 `HOST-IOURING-FILEOP`；普通 syscall 不会重复触发 |
| enrichment TOCTOU（秒退进程 cmdline 读不到/读半截） | **已修复** | exec 探针**内核态采集 argv**（`mm->arg_start..arg_end`），`/proc` 仅在为空时兜底；秒退进程实测 20/20 命中 |
| 容器/PID 命名空间逃逸采集 | **GAP** | Agent 必须运行在主机命名空间；需部署约束/校验 |
| 路径型 fanotify 规则被别名/挂载规避 | **PART** | 关键文件建议按 inode 而非路径 |

## 4. 破坏审计与证据

| 手法 | 状态 | 说明 |
|---|---|---|
| 篡改 `events.jsonl` | **DETECT**（哈希链 + 锚定） | `edrctl events verify` 报 `hash_mismatch/seq_gap` |
| **重算整条链 / 篡改事件内容** | **DETECT（HMAC，`--audit-key-file`）** | 已接线：无 key 或有错 key 无法伪造/校验通过（`edrctl events verify --key-file`）。**残余**：root 可读主机上的 key → 需 TPM/外部密钥才能对抗 root |
| 截断日志并同步锚定 | **检测（远程锚定）** | 中心 `/v0/center/anchor` 作为**单调远程锚点**（拒低下调）+ 中心 seq 连续性；本地文件锚定仍可被 root 改写 |
| 杀 Agent 让日志断流 | **DETECT（需中心侧）** | 中心应基于“失联/心跳”告警（本轮尚未实现） |
| 伪造/重放中心请求 | **BLOCK**（HMAC + 时间窗 + requestID 防重放；**本轮 query 也纳入签名**） | 重启后 60s 窗口内重放为残余风险 |
| 中间人篡改中心**响应**（注入 kill 动作） | **BLOCK**（本轮新增响应体签名 `X-EDR-Response-Signature`） | 覆盖 Agent 动作轮询；查询/摄取仍建议叠加 TLS |
| 从 argv 读取 token/secret（同机用户） | **缓解**（本轮新增 `--token-file`/`--secret-file`） | 文档改用文件形式；旧 `--token` 仍可用 |

## 5. 利用 EDR 自身（滥用/DoS）

| 手法 | 状态 | 说明 |
|---|---|---|
| 共享密钥（任一主机 root 可读）横向查询/注入/编排他机动作 | **GAP（设计）** | 建议 mTLS + 每主机凭据 + 动作双人授权 |
| 动作编排注入 | **BLOCK**（封闭枚举 + 审批 + 响应签名） | 审批与请求均需密钥 |
| 灌满磁盘使审计写入失败 | **PART** | 写失败会记录错误，但未告警；建议配额/告警 |
| 资源耗尽（跟踪器无界） | **修复**（本轮 TTL 剪枝） | 地址表曾无界 |
| 端口/连接隐藏检测误报 | **缓解** | `--rootkit-connections` 默认关闭 |

## 6. 本轮已加固（红队触发）

1. 严格模块加载拦截 `--strict-modules`（真机：`insmod` → `Operation not permitted` + 守卫留痕）。
2. datapath 存活哨兵（真机：杀 datapath → SOS）。
3. 丢事件告警 `dropWatchLoop`（防洪水致盲，不再静默）。
4. 请求签名覆盖 **query**；中心动作**响应体签名**并在 Agent 侧校验（防 MITM 注入 kill）。
5. `--token-file` / `--secret-file`（密钥不再经 argv）。
6. 既有：pidfd 守卫、bpf_guard attach 族、LSM、锚定 fail-closed、跟踪器剪枝。
7. **审计 HMAC 接线**（`--audit-key-file`，无 key 无法伪造）+ **中心远程锚点**（单调、防下调、响应签名）+ `edrctl events verify` 支持 `--key-file`/`--anchor-url`。

## 7. 推荐的宿主机加固（EDR 之外）

- 安全启动 + IMA/EVM + `kernel.modules_disabled=1` 或模块签名强制。
- Kernel lockdown（`lockdown=confidentiality/integrity`）、`CONFIG_STRICT_DEVMEM`。
- GRUB 口令；`bpf` 加入 `lsm=`（启用本 EDR 的 LSM 层）。
- 中心：mTLS + 每主机密钥 + 远端锚定 + 失联告警；存储配额。
- 只读根 / 最小镜像；限制 `CAP_SYS_MODULE`、`CAP_SYS_RAWIO`、`CAP_SYS_PTRACE` 的持有者。

## 8. 已知不可本地完全防御

获得 root 且能加载内核模块 / 写内核内存 / 改启动链的对手，理论上可压制任何本地主机 EDR。本方案的目标是：**提高成本、保证“被压制可见”（SOS/告警/审计）、并检测实际攻击行为**，同时通过 `--strict-modules`、LSM、安全启动把边界尽量外推。
