# EDR v2 架构规划与迁移方案

> 来源基线：`~/EDR-Linux-master`（v0.9.1）
> 目的：提炼旧项目优劣 → 重新规划更合适的架构 → 制定可执行的迁移路径

---

## 1. 旧项目（v0.9.1）回顾

### 1.1 值得继承的设计（优势）

| # | 设计点 | 为什么值得保留 |
|---|--------|----------------|
| S1 | **分层架构**：采集 / 检测 / 响应 / 审计 / 控制面 / 自保护 清晰分离 | 包边界干净，职责可辨，便于演进与独立测试 |
| S2 | **两阶段评估**：ring0 黑名单 fast-path + 用户态 `EvaluateAll` 全规则 | 兼顾毫秒级阻断与复杂规则覆盖，是 EDR 的正确形态 |
| S3 | **能力接口 + 依赖注入**：`EventSource`/`DecisionEngine`/`ActionExecutor`/`Loader`/`MapFiller` | 解耦彻底，可用 stub 做单测，支持分级部署 |
| S4 | **TOCTOU 意识**：pidfd kill、fd 级 fchmod、O_PATH 隔离、symlink base 拒绝 | 安全意识正确，方向正确（只是个别实现有 bug） |
| S5 | **审计链**：SHA-256 hash chain + HMAC + 轮转校验 + 远端锚定概念 | 主机侧取证防篡改的标准解法 |
| S6 | **策略签名**：Ed25519，agent 仅持有公钥 | 公钥/私钥分离，符合最小权限 |
| S7 | **多层自保护矩阵**：LSM + kprobe override + fanotify inode + systemd 硬化 | 纵深防御思路正确 |
| S8 | **fail-open 兜底**：fanotify panic recover 默认 ALLOW、BPF 失败降级 procfs | 保证系统可用性的正确取向 |
| S9 | **HA 概念**：split A/B + supervisor quorum + lease/liveness | 内网实战的差异化能力，值得保留 |
| S10 | **工程资产**：每包单测、研究文档、攻防分析、JSON Schema | 有沉淀，可作为新项目的知识输入 |

### 1.2 必须在 v2 规避的问题（按根因归类，非逐条 bug）

| 根因 | 表现 | v2 对策 |
|------|------|---------|
| **宣称 ≠ 实现** | SelfCheck/SOS 未接线、`lsm_bpf_guard` 未 attach、anchor 传 nil、`self_protect_blocks` 恒 0、heartbeat 逻辑必误报 | 建立**能力矩阵 + e2e 验收测试**，每个宣称能力必须有对应可执行测试；CI 强制 |
| **单体膨胀** | `agent.go` 1701 行、`server.go` 1630 行、`edrctl` 1404 行 | 从一开始按领域拆包/拆文件，单文件软上限 ~400 行 |
| **默认不安全** | `bpf_guard` 默认开且拦所有进程的 map 写入；LSM 拦所有信号；默认弱共享密钥；supervisor secret 空则 fail-open | **安全默认 + 精确目标**：只拦自己的对象、显式 enable、空密钥拒绝启动 |
| **内核绑定** | 依赖预编译 `vmlinux.h`，跨内核需重编，无 CO-RE | 采用 **CO-RE + BTF**，纯 Go loader（推荐 cilium/ebpf） |
| **门禁不可复现** | `audit-ready` 依赖缺失文件、`vmlinux.h` 不入库、CI 只测 2 个包 | 可复现构建（pin 工具链）+ 全量 CI + 容器化 BPF 编译 |
| **背压缺失** | channel 满静默丢弃（deferred eval、fast path、response） | 显式背压策略 + 丢事件计数器 + 告警 |
| **存储弱** | 仅 JSONL 顺序扫描，无查询 | 抽象 Sink 接口；JSONL 默认，可选 ClickHouse/OTLP |
| **文档漂移** | README/STATUS/代码三方数字互相矛盾 | 单一事实源：由代码/测试生成的 capability 文档 |
| **误用模糊** | fanotify 关键路径整目录 bypass、TTY 启发式 | 最小白名单 + 显式策略；启发式仅作加分项不作放行依据 |

---

## 2. v2 设计目标与原则

### 2.1 设计原则

1. **可验证性优先**：任何"能力"必须先有验收测试，才允许写入文档。
2. **最小精确强制执行**：阻断只作用于明确目标（自己的 BPF 对象、明确的进程/路径），
   禁止"拦截全系统某类操作"式的暴力策略。
3. **安全默认**：默认拒绝空密钥、默认精确目标、危险开关默认关闭且需显式开启。
4. **可观测**：所有丢弃/降级/拒绝都要有指标与审计事件，不允许静默。
5. **可复现**：构建产物与门禁在干净环境可复现，工具链版本 pin 死。
6. **fail-safe 方向明确**：遥测可 fail-open，强制路径必须 fail-closed 且有回滚；
   两者在代码中必须显式标注。
7. **内核可移植**：CO-RE + BTF，一次编译多内核运行。

### 2.2 技术选型（提议）

| 层 | 旧方案 | v2 提议 | 理由 |
|----|--------|---------|------|
| 主语言 | Go + cgo/libbpf | Go（保留） | 并发模型/静态编译优势；重写的是"用法"不是语言 |
| BPF 加载 | cgo + libbpf + vmlinux.h | **cilium/ebpf（纯 Go）+ CO-RE** | 免 cgo、交叉编译、构建可复现；社区主线 |
| BPF 源 | `.bpf.c` + 预生成 vmlinux.h | `.bpf.c` + CO-RE 宏，`bpf2go` 生成 | 消除内核头强绑定 |
| 事件结构 | 手写 330B 结构体 | `bpf2go` 生成的结构体 + 版本字段 | 消除 C/Go 手工对齐漂移 |
| 规则引擎 | 自定义 JSON + 扁平 Match | 分层 DSL（宏/AND/OR/NOT）+ 事件类型索引 | 可读性/可复用/性能 |
| 强制路径 | LSM + kprobe override 混用 | **LSM 主路径**（精确目标）+ kprobe 兜底 | LSM 是官方推荐、语义清晰 |
| 存储 | JSONL | Sink 接口：JSONL 默认 / ClickHouse 可选 | 兼顾轻量与会话查询 |
| HA/传输 | 自定义 HMAC + Unix socket | 保留模型，密钥强制、可选 mTLS | 复用成熟概念 |

### 2.3 Go / Rust 职责边界（已决策：混合）

混合语言的风险在于 **IPC 复杂度会吃掉安全性收益**。因此边界必须沿"故障域 + 变更频率"
切分，而不是"哪块难写用哪块"。推荐按 **数据面（Rust）/ 控制面与大脑（Go）** 切：

| 归属 | 组件 | 理由 |
|------|------|------|
| **Rust（数据面 / 永不阻塞的强制路径）** |① BPF 加载与 ringbuf 消费（aya 或直接用 cilium/ebpf 的 C 探针 + Rust 消费）；② fanotify FAN_OPEN_PERM 同步决策路径；③ 响应原语：pidfd kill / quarantine / nft / suspend；④ guardian 与自保护哨兵 | 这些路径对**内存安全、无 GC 停顿、崩溃即失守**最敏感；Rust 的 `Result`/`no_std` 风格有利于"证明不会 panic 阻塞内核" |
| **Go（控制面 / 大脑）** |① 事件管线编排与富化；② 检测引擎（规则 DSL/索引）；③ 策略解析/签名/热重载；④ 审计链/锚定；⑤ 控制面 HTTP-over-Unix-socket + CLI；⑥ HA/supervisor；⑦ 指标 | 高迭代、高 IO、并发编排、生态成熟；旧项目已验证 Go 适配这些层 |
| **C（BPF 程序）** | 全部 `.bpf.c` 探针（CO-RE） | 内核态只能是 C/汇编；由 Rust 侧用 aya/或 Go 侧用 cilium/ebpf 加载 |

**两者通信**：Unix domain socket（长度前缀 + 版本化 protobuf/flatbuffer），
或 Rust 侧暴露 ringbuf 之上的第二级 ring。要求：**有界背压 + 丢帧计数 + 协议版本字段**。

> 备选边界（若想降低 IPC 复杂度）：Rust 仅承担"fanotify + 响应原语"的一个小守护进程，
> 其余全部 Go，BPF 由 Go 的 cilium/ebpf 加载。**推荐先用这个更小的边界起步**，
> 等 M1-M3 跑通再决定是否把 ringbuf 消费也迁到 Rust。

> BPF 加载器已决策：**cilium/ebpf + CO-RE**（纯 Go 加载）。若后续引入 aya，需要评估
> 两套 loader 的共存成本，M0 阶段先只保留 cilium/ebpf。

---

## 3. 目标架构

```
┌────────────────────────────────────────────────────────────┐
│  控制面 (control plane)                                     │
│  Unix sock + SO_PEERCRED | admin token(nonce 防重放) | 策略签发 │
└───────────────┬────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────┐
│  事件管线 (staged pipeline, 有界背压 + 指标)                  │
│  decode → enrich(/proc) → detect(规则索引) → respond → sink    │
└───────┬───────────────────────────────┬────────────────────┘
        │                               │
┌───────▼────────┐             ┌────────▼─────────┐
│ 检测引擎        │             │ 响应引擎          │
│ 事件类型索引    │             │ 精确目标 + 回滚    │
│ DSL 条件        │             │ pidfd/nft/quarantine│
│ (序列规则预留)  │             │ (每动作有 dry-run)  │
└────────────────┘             └──────────────────┘
        ▲                               ▲
┌───────┴───────────────────────────────┴────────────────────┐
│  采集层 (CO-RE eBPF + fanotify + procfs fallback)            │
│  ringbuf 统一事件总线 | 采集侧粗筛 | 每探针独立 enable         │
└────────────────────────────────────────────────────────────┘
        ▲
┌───────┴────────────────────────────────────────────────────┐
│  自保护 (只保护"自己的对象")                                  │
│  own_bpf_obj map(注册自身 prog/map id) | 周期 heartbeat 探针    │
│  LSM task_kill/ptrace/security_bpf(仅自家对象) | fanotify 哨兵 │
└────────────────────────────────────────────────────────────┘
        ▲
┌───────┴────────────────────────────────────────────────────┐
│  审计 (chain + HMAC + 单调 seq + anchor 强制接线)             │
│  完整性哨兵真正接线 | 截断/降级可检测 | SOS 实际落盘+签名        │
└────────────────────────────────────────────────────────────┘
```

### 3.1 关键设计决策（针对旧项目痛点）

- **自保护对象识别**：建立 `own_bpf_objs` map，在加载时注册自身全部 prog/map id；
  `security_bpf` LSM 仅当 `attr` 指向自家对象且调用者非 agent 时才拒绝。
  → 既封堵 `link/prog detach` + `map update/delete`，又不影响系统其他 BPF 使用者
  （修正旧项目 #5/#6/#7 与"过宽拦截"）。
- **心跳由专用探针产生**：新增 `tp/syscalls/sys_enter_getpid` 或 `raw_tp` 定时触发写
  `agent_heartbeat`，而非仅攻击时写。→ 修正旧项目 #2。
- **信号策略白名单化**：仅阻断针对 agent 的致命/停管信号，保留 systemd/运维的合法
  停机路径（或提供"受控停机遇 LSM 放行"的显式通道）。→ 修正旧项目 #8。
- **pidfd 探针必须解析目标**：从 pidfd 反查目标 task，仅当目标是 agent 才拦。→ 修正 #4。
- **锚定对象在 server 构造前创建**（依赖注入顺序测试覆盖）。→ 修正 #3。
- **链校验拒绝降级**：没有 `integrity_version` 的行只能出现在 chain 起点之前；
  一旦进入 chain，后续缺失版本视为 `malformed`；校验 seq 连续 + anchor 比对。→ 修正 #14。
- **fanotify 新目录继承 + 收窄 bypass**：新建目录自动挂 mark；"关键路径"改为最小白名单，
  PAM/SSH 等仅放行已知只读工具而非整目录。→ 修正 #12。

### 3.2 建议目录结构（Go）

```
EDR/
├── cmd/
│   ├── edr-agent/        # 单机 agent（主入口）
│   ├── edrctl/           # CLI
│   ├── edr-sensor/       # split 数据面
│   ├── edr-enforcer/     # split 执行面
│   ├── edr-orchestrator/ # HA 编排
│   └── edr-supervisor/   # 远程仲裁（可选）
├── internal/
│   ├── event/            # 事件模型 + 版本常量（单一事实源）
│   ├── collect/          # procfs / fanotify / inotify 采集
│   ├── bpf/              # CO-RE 探针 + bpf2go + loader
│   ├── pipeline/         # 阶段化事件管线 + 背压
│   ├── detect/           # 规则引擎（索引 + DSL）
│   ├── respond/          # 响应动作（各自可 dry-run）
│   ├── audit/            # chain + HMAC + anchor + verify
│   ├── integrity/        # 哨兵 + SOS（必须接线）
│   ├── protect/          # own_bpf_objs + 自保护策略
│   ├── control/          # HTTP over Unix sock + 认证
│   ├── policy/           # 策略解析/签名/校验
│   ├── notify/           # webhook/email/syslog
│   ├── metrics/          # Prometheus
│   └── platform/         # procutil / pidfd / cgroup / namespace 工具
├── configs/              # 示例配置
├── deploy/               # systemd / 安装脚本
├── docs/                 # 设计 + 能力矩阵（由测试生成）
├── test/                 # e2e / 能力验收 / 红队回归
└── tools/                # 构建与门禁脚本
```

---

## 4. 迁移策略

采用 **"新骨架 + 选择性移植"（greenfield + 复用）**，而非全量重写或原地改：

### 4.1 可复用（移植后加固）

| 旧模块 | 处理 |
|--------|------|
| `internal/policy`（匹配/优先级/effect） | 移植并扩展为 DSL；补单测 |
| `internal/eventlog` 的 hash chain/HMAC | 移植后**修复降级/截断**；加 seq 连续校验 |
| `internal/integrity/sign.go`（Ed25519） | 基本可直接复用 |
| `internal/adminauth`（HMAC token） | 复用 + 增加 nonce 防重放 |
| `internal/procutil`、pidfd、cgroup 解析 | 复用并增强 namespace 校验 |
| `internal/response/nft.go` 的参数化构造 | 复用（已是 `[][]string`，安全） |
| `internal/notify`、`internal/metrics` | 复用 |
| `internal/collector` 的 procfs/inotify | 复用，重做背压与事件模型 |

### 4.2 重写

- **BPF 层**：全部改为 CO-RE + bpf2go + cilium/ebpf；事件结构由生成代码管理。
- **agent 核心**：拆分为 pipeline/detect/respond/protect 独立包。
- **控制面**：按 handler 域拆分文件，统一认证中间件。
- **自保护**：按 §3.1 的"精确目标"模型重写。
- **fanotify**：重写 mark 继承与 bypass 逻辑。

### 4.3 迁移阶段（里程碑）

| 阶段 | 目标 | 验收 |
|------|------|------|
| M0 骨架 | 目录结构、event 模型、构建/CI/门禁、能力矩阵模板 | `make gate` 在干净环境绿灯 |
| M1 采集 | CO-RE exec/connect/fork/exit + procfs 富化 + 管线背压 | 实机事件流入 + 丢事件指标 |
| M2 检测 | 规则引擎 + DSL + 事件类型索引 + 策略签名 | 规则单测 + 精度/召回样本 |
| M3 响应 | kill(pidfd 目标校验)/quarantine/nft/isolate + dry-run | 每个动作 e2e + 回滚 |
| M4 审计 | chain + seq + anchor 强制接线 + verify 拒绝降级 | 篡改/截断/降级用例全部检出 |
| M5 自保护 | own_bpf_objs + LSM 精确拦截 + 周期心跳 + 哨兵接线 | 攻防回归：detach/delete/信号/伪装 |
| M6 控制面 | Unix sock + SO_PEERCRED + admin token(防重放) | 认证绕过测试 |
| M7 HA/分发 | split A/B + supervisor + 强密钥/mTLS | 故障切换演练 |

### 4.4 迁移原则

- **旧仓库只读**：作为参考与代码来源，不作为新仓库历史。
- **一次只搬一个模块**，搬完即补测试与文档，避免再次"宣称先行"。
- **能力矩阵**：`docs/capability-matrix.md` 由测试结果生成，杜绝文档漂移。
- **先窄后宽**：默认只保护 agent 自身 + 少数高危路径，再按需扩展。

---

## 5. 已确认的决策

| 项 | 决策 |
|----|------|
| 主语言 | **Go + Rust 混合**（边界见 §2.3） |
| BPF 加载 | **cilium/ebpf + CO-RE**，纯 Go 加载 |
| 首期范围 | **聚焦单机核心闭环**（采集→检测→响应→审计→自保护→控制面）；HA/中心化后置 |
| 验证环境 | **有 root Linux 测试机**，可做 M1/M5 实机回归 |
| 旧仓库 | **保持只读**，仅作参考与代码来源 |

## 6. M0 交付物清单（骨架与门禁，待确认后开工）

1. `go.mod`（module path 待定）+ `Cargo.toml`（若引入 Rust 守护）与目录骨架（§3.2）
2. `internal/event`：版本化事件模型（单一事实源），附 schema 测试
3. `internal/pipeline`：阶段化管线 + 有界背压 + 丢事件指标（先接 fake 源）
4. `internal/detect`：从旧 `policy` 移植的规则引擎 + 索引雏形 + 单测
5. `internal/audit`：移植并修复 hash chain（seq 连续、拒绝降级）+ 单测
6. `Makefile` + `tools/`：**可复现**构建、`gofmt/vet/errcheck/test`、BPF 编译容器化
7. `.github/workflows/ci.yml`：**全量**包测试（不再只测 2 个包）
8. `docs/capability-matrix.md`：由测试结果生成的模板（当前全为"未实现"）
9. `test/capability/`：能力验收测试脚手架

**M0 验收**：干净环境 `make gate` 全绿；`capability-matrix` 由测试生成且无人工条目。

## 7. 仍需确认

1. **Rust 边界**：先采用"小边界"（Rust 仅 fanotify+响应原语守护），还是直接上"数据面全 Rust"？
2. **Go module path**（如 `github.com/<you>/edr` 或本地 `edr`）。
3. 是否现在就生成 M0 骨架代码。
