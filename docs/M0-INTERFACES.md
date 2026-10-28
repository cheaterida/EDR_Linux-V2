# M0 接口设计与骨架方案（评审稿）

> 状态：**待评审，尚未生成代码**
> 对应里程碑：M0（骨架 + 门禁 + 单机核心闭环的接口契约）

本文定义 v2 的**包边界、核心接口、数据模型与 Rust 小边界 IPC 协议**。
目标是让 M0 一开工就有稳定的契约，避免旧项目"接口漂移 → 文档漂移"的复现。

---

## 0. 落地约定

- Go module path：`edr`（本地；若需发布再改）。
- 单文件软上限 400 行；单包职责单一。
- 所有 channel 必须有界 + 有 `Dropped` 指标；禁止静默丢弃。
- 所有"强制路径"与"遥测路径"在代码注释中用 `// FAIL-CLOSED` / `// FAIL-OPEN` 显式标注。
- 所有能力由 `test/capability` 生成 `docs/capability-matrix.md`。

---

## 1. 目录骨架

```
EDR/
├── go.mod
├── Makefile
├── internal/
│   ├── event/        # 事件模型 + Kind 常量 + 版本（单一事实源）
│   ├── collect/      # procfs / inotify / fanotify(client) / bpf(loader)
│   ├── bpf/          # CO-RE 探针 (bpf.c) + bpf2go 产物 + Loader
│   ├── pipeline/     # 阶段化管线 + 背压 + 指标
│   ├── detect/       # 规则引擎（索引 + 条件树）
│   ├── policy/       # 策略解析 / 校验 / Ed25519
│   ├── respond/      # 响应动作（含 Rust 客户端与本地实现）
│   ├── audit/        # chain + HMAC + anchor + verify
│   ├── protect/      # own_bpf_objs + 自保护策略
│   ├── control/      # HTTP over Unix sock + 认证
│   ├── notify/       # webhook/email/syslog
│   ├── metrics/      # Prometheus
│   └── platform/     # procutil / pidfd / cgroup / ns
├── cmd/
│   ├── edr-agent/
│   └── edrctl/
├── datapath/         # Rust 小边界守护（fanotify + 响应原语）
│   ├── Cargo.toml
│   └── src/
├── configs/
├── deploy/
├── docs/
├── test/capability/
└── tools/
```

---

## 2. 事件模型（`internal/event`）

### 2.1 Kind 枚举

```go
type Kind uint16

const (
    KindUnknown     Kind = 0
    KindExec        Kind = 1
    KindConnect     Kind = 2
    KindFork        Kind = 3
    KindExit        Kind = 4
    KindSelfProtect Kind = 5
    KindPtrace      Kind = 6
    KindLDPreload   Kind = 7
    KindInstrument  Kind = 8
    KindPrivesc     Kind = 9
    KindModuleLoad  Kind = 10
    KindModuleUnload Kind = 11
    KindBPFOp       Kind = 12
    KindFileOp      Kind = 13
    // 预留：KindMount, KindNamespace, KindOpenat2 ...
)
```

> 与旧项目的差别：Kind ↔ 值绑定集中在此，C 侧由 `bpf2go` 生成或由 `//go:generate`
> 从单一清单生成两侧常量，杜绝手工漂移。

### 2.2 Event 主结构

```go
type Event struct {
    SchemaVersion string    // "v2.0"，写入/校验两侧一致
    Kind          Kind
    Time          time.Time // 采集侧时间

    // 主体（进程）
    PID, TGID, PPID uint32
    UID, EUID       uint32
    Comm            string

    // 可选富化（nil 表示未采集）
    Proc *ProcInfo   // Exe/Cmdline/Environ/Maps/CapEff/ContainerID/StartTicks
    Net  *NetInfo    // Family/RemoteAddr/RemotePort/LocalPort/Protocol/State
    File *FileInfo   // Path/Op/Mode/Inode/Device

    // 自保护/根因溯源
    Detail map[string]any // 探针特有字段（ptrace request、bpf cmd、signal 等）

    // 审计链（仅在被 Seal 后填充）
    Chain *ChainMeta
}

type ProcInfo struct {
    Exe         string
    Cmdline     []string
    Environ     []string   // 按需，注意泄露面
    MapsLibs    []string   // 仅关键字行
    CapEff      uint64
    ContainerID string
    StartTicks  uint64
    Namespace   NamespaceIDs // pid/mnt/net/user/...
}

type NetInfo struct {
    Family     uint8
    Protocol   string // tcp/udp
    RemoteAddr string
    RemotePort uint16
    LocalPort  uint16
    State      string
}

type FileInfo struct {
    Path   string
    Op     string // open/create/write/delete/rename/...
    Mode   uint32
    Inode  uint64
    Device uint64
}
```

**设计取舍**
- 用 typed 子结构 + `Detail map` 兜底，而非旧项目的"全塞 map[string]any"。
- `Environ`/`MapsLibs` 默认**不填充**（隐私与性能），仅当规则需要时由 enrich 阶段按需拉取。
- `NamespaceIDs` 从 M0 就纳入，规避旧项目"S22 未验证 PID namespace"。

---

## 3. 采集源（`internal/collect/`）

```go
// 事件流式源（BPF / fanotify 客户端 / inotify）
type Source interface {
    Name() string
    Events(ctx context.Context) <-chan event.Event
    Close() error
}

// 快照式源（procfs）
type Snapshotter interface {
    Snapshot(ctx context.Context) (Snapshot, error)
}

type Snapshot struct {
    Processes   []Process
    Connections []Connection
    Files       []FileChange
}
```

- `MergedSource` 合并多个 `Source`，**带丢帧计数**（每个源独立 `dropped_total`）。
- BPF `Loader` 接口（cilium/ebpf 实现）：

```go
type Loader interface {
    Load(spec LoadSpec) error
    Close() error
    Ringbuf(ctx context.Context) <-chan event.Event // 解码后
    Status() Health
    // 自保护相关
    RegisterOwnObjects() (OwnObjectSet, error)
    SetAgentPID(pid uint32) error
// 精确开关：每个探针独立 enable
    Enable(probe Probe, on bool) error
}
```

> 对比旧项目：旧 `Loader` 无"每探针 enable"、无"own objects 注册"，正是自保护过宽/缺失的根因。

---

## 4. 管线（`internal/pipeline/`）

```go
type Stage interface {
    Name() string
    // 返回 (可能被修改的事件, 是否继续)；error 表示该事件处理失败但不 panic
    Handle(ctx context.Context, ev *event.Event) (keep bool, err error)
}

type Pipeline struct {
    stages []Stage
    in     chan event.Event
    stats  *Stats
}

type Stats struct {
    In, Out, Dropped, Errored uint64
    PerStageLatency           map[string]Histogram
}
```

- **有界背压**：`in` 为有界 channel；满时按策略：
  - **遥测类事件**：丢弃并 `Dropped++`（FAIL-OPEN，有指标）；
  - **强制类事件（SelfProtect 等）**：走独立高优先通道，不共享有界队列（FAIL-CLOSED）。
- 标准阶段顺序：`decode → enrich → detect → respond → sink`。
- `enrich` 只做规则**声明需要**的字段（由 detect 的字段索引驱动）。

---

## 5. 检测引擎（`internal/detect/` + `internal/policy/`）

```go
type Field string
const (
    FieldProcessName Field = "process_name"
    FieldProcessPath Field = "process_path"
    FieldCmdline     Field = "cmdline"
    FieldParentName  Field = "parent_name"
    FieldEnviron     Field = "environ"
    FieldMapsLibs    Field = "maps_libs"
    FieldFilePath    Field = "file_path"
    FieldRemoteAddr  Field = "remote_addr"
    // ...
)

// 条件树
type Node interface{ isNode() }
type And struct{ Nodes []Node }
type Or  struct{ Nodes []Node }
type Not struct{ Node Node }
type Pred struct {
    Field Field
    Op    Op // equals/not_equals/contains/starts_with/ends_with/regex/gt/lt...
    Value string
}

type Rule struct {
    ID, Category, Severity, Decision, Action string
    Priority int
    Effect   []string // audit / response
    When     Node
    Enabled  bool
}

type Engine struct {
    byKind map[event.Kind][]*Rule // 事件类型倒排索引（借鉴 Falco/Tracee）
    all    []*Rule
}

func (e *Engine) Match(ev *event.Event, pol *policy.Policy) []Rule
```

- **事件类型索引**解决旧项目"全量遍历规则"的性能问题。
- 条件树取代旧项目扁平 `Match`（无法表达 AND/OR/NOT）。
- 每个 `Pred` 声明其 `Field`，供 enrich 阶段做"最小富化"。
- 序列规则（行为链）留 `SequenceRule` 接口，M2 之后实现。

---

## 6. 响应（`internal/respond/`）

```go
type Action string // kill/kill_tree/quarantine/nft_block/network_isolate/process_suspend/fix_permissions/fanotify_deny

type Request struct {
    Action     Action
    PID        uint32
    ProcessExe string
    StartTicks uint64  // 身份校验
    Path       string
    RuleID     string
    // ...
}

type Result struct {
    Action  Action
    Success bool
    Detail  string
    Enforced bool // false = dry-run/仅记录
}

type Responder interface {
    Apply(ctx context.Context, req Request) Result
}
```

- **每个动作自带 DryRun**，且 `Result.Enforced` 明确区分"真执行 / 仅记录"，
  避免旧项目"dry-run 却把指标算作 block"的失真。
- `kill` 必须"目标校验"：`StartTicks`/`Exe` 匹配后才通过 pidfd 发信号。
- fanotify 同步决策**不在 Go 内实现**，由 Rust 小边界守护承担（见 §8）。

---

## 7. 审计（`internal/audit/`）

```go
type Sink interface {
    Write(ctx context.Context, ev *event.Event) error
    Close() error
}

type ChainMeta struct {
    ChainID  string
    Seq      uint64
    PrevHash string
    Hash     string
    HMAC     string
}

type Chain interface {
    Seal(ev *event.Event) error
    Snapshot() Head
    Verify(sink Sink) (VerifyResult, error) // 校验 seq 连续 + 拒绝降级 + HMAC + anchor 比对
}

type Anchor interface {
    Push(head Head) error
    Fetch() (*Head, error)
    CrossVerify(local Head) []Issue
}
```

**相对旧项目的强制改进**
1. 一旦进入 chain，缺失/不匹配 `integrity_version` 的行判为 `malformed`（不再静默当 legacy）。
2. `Verify` 校验 `Seq` 单调连续，发现跳号即报 `seq_gap`。
3. `Anchor` 在 server 构造**之前**创建（依赖注入顺序由测试保证）。
4. `Verify` 默认与 anchor `CrossVerify`。

---

## 8. Rust 小边界守护（`datapath/`）

### 8.1 职责（仅此三件）

1. **fanotify `FAN_OPEN_PERM` 同步决策**（本地决策，避免每次 open 都走 IPC）。
2. **响应原语**：pidfd kill / quarantine / nft 调用。
3. **guardian/哨兵**：心跳与自愈。

### 8.2 决策模型（关键）

Go 是"大脑"，Rust 是"手脚"。为让 fanotify 保持低延迟，**不在每次 open 时回 Go**，
而是：

```
Go 编译策略 → policy_snapshot(紧凑决策表) → push 给 Rust
Rust 本地匹配 → 同步 FAN_ALLOW/FAN_DENY → 异步 stream 事件回 Go 审计
Go 需要命令式动作(kill/quarantine) → request 给 Rust → Rust 执行 → result 回 Go
```

### 8.3 IPC 协议（Unix socket，长度前缀 + 版本化）

```
Frame := [u32 length][u8 version][u8 msgType][payload: JSON(protobuf 预留)]

msgType:
  0x01 HELLO            Go → Rust：协议版本、agent pid、能力协商
  0x02 POLICY_SNAPSHOT  Go → Rust：{version, file_rules[], self_protect_paths[]}
  0x03 EVENT            Rust → Go：fanotify/enforcement 事件（审计）
  0x04 ACTION_REQ       Go → Rust：{id, action, pid, exe, start_ticks, path}
  0x05 ACTION_RESULT    Rust → Go：{id, success, enforced, detail}
  0x06 HEARTBEAT       双方互发
```

**约束**
- 每条消息带 `version`；未知版本 → 拒绝并审计（不静默）。
- 有界发送队列；满时对 `EVENT` 丢弃并计数，对 `ACTION_REQ` 返回失败（不假装成功）。
- fanotify 决策超时/守护不可达 → **FAIL-OPEN（ALLOW）+ 高优告警**（保证可用性）。

### 8.4 Rust 侧 crate 轮廓

```
datapath/
├── Cargo.toml
├── src/
│   ├── main.rs        # 启动、socket 服务、信号
│   ├── ipc.rs         # 帧编解码 + 版本
│   ├── policy.rs      # 决策表 + 本地匹配
│   ├── fanotify.rs    # FAN_OPEN_PERM（nix crate）
│   ├── action.rs      # pidfd/quarantine/nft
│   └── guardian.rs    # 心跳/自愈
```

---

## 9. 控制面（`internal/control/`）

- 单入口 `http.Handler`，按域拆分文件（`events.go/policy.go/respond.go/admin.go`）。
- 认证中间件：
  - `PeerAuth`（`SO_PEERCRED` + allowed uids），
  - `AdminAuth`（HMAC token + **服务端 nonce 去重**，禁止 URL query 传 token）。
- 所有写操作审计到 chain。

---

## 10. 能力矩阵与门禁

### 10.1 能力测试约定

- `test/capability/*_test.go` 在**实机**运行，产出 `Result{Name, Passed, Detail}`。
- `make capability` 聚合为 `docs/capability-matrix.md`（**无人工条目**）。

### 10.2 `make gate` 组成

```
fmt → vet → errcheck → unit test → build (go + cargo) → bpf-compile
→ capability (需 root，CI 可选/VM 跑)
```

### 10.3 CI

- 全量包 `go test ./...` + `cargo test`；
- BPF 编译在固定版本容器内完成（可复现）；
- 实机能力测试由独立 workflow（self-hosted root runner / VM）执行。

---

## 11. M0 文件级任务清单

| # | 路径 | 内容 |
|---|------|------|
| 1 | `go.mod` | module `edr`，Go 1.23 |
| 2 | `internal/event/event.go` | Kind/Event/ProcInfo/NetInfo/FileInfo + 版本 |
| 3 | `internal/event/event_test.go` | 序列化往返、版本校验 |
| 4 | `internal/pipeline/pipeline.go` | Stage/Stats/有界管线 |
| 5 | `internal/pipeline/pipeline_test.go` | 背压与丢弃计数 |
| 6 | `internal/policy/*` | 从旧项目移植解析/签名，扩展条件树 |
| 7 | `internal/detect/engine.go` | 事件类型索引 + Match |
| 8 | `internal/detect/engine_test.go` | 索引命中、优先级、NOT |
| 9 | `internal/audit/chain.go` | 移植 + seq 连续 + 拒绝降级 |
| 10 | `internal/audit/chain_test.go` | 篡改/截断/降级用例 |
| 11 | `Makefile` + `tools/*` | 门禁与可复现构建 |
| 12 | `.github/workflows/ci.yml` | 全量测试 |
| 13 | `test/capability/` + 生成器 | 能力矩阵模板 |
| 14 | `datapath/` | Rust 骨架（socket + ipc + guardian 空实现） |

> 说明：#3/#5/#8/#10 是与旧项目缺陷直接对应的"防回归"测试，M0 必须带。

---

## 12. 评审关注点

请在评审时重点确认：

1. 事件模型字段是否够用/过度（尤其 `Environ`/`MapsLibs` 的按需富化）。
2. fanotify 采用"Go 编译决策表 + Rust 本地匹配"是否符合预期（vs 每次同步 IPC）。
3. 强制类事件独立高优通道是否会带来复杂性，是否接受。
4. M0 是否需要一次性搭起 Rust `datapath` 骨架，还是 M0 仅 Go、`datapath` 放 M1。
5. `make gate` 中 `capability` 是否纳入本地默认（需 root）还是仅 CI。
