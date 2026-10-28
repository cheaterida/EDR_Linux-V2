# 审计运营中心（Audit Operations Center）设计思路

> 定位：M8 阶段。本文给出**设计思路与取舍**，供评审；不代表立即实现。
> 参照：旧项目 `docs/blue-team-ops-center.md`（单机 supervisor + 人工 CLI + 手工关联）。

---

## 1. 定位与目标

| 维度 | 目标 |
|------|------|
| 角色 | 多主机的**信任锚 + 汇聚 + 关联 + 研判 + 处置编排 + 取证留痕**中心 |
| 不做什么 | 不在中心做内核强制；强制留在各 agent（数据在边缘，决策可边缘化） |
| 首要约束 | **可验证性**：中心是所有 agent 哈希链的锚定方，能检测主机侧截断/篡改 |
| 交互形态 | **CLI 优先**（`edrctl` 连中心），Web UI 后置 |
| 演进 | 单机中心 → 高可用中心（Active/Standby）→ 可选多租户 |

**与旧项目的关键差异**

| 旧项目 | v2 中心 |
|--------|---------|
| supervisor 仅做日志汇聚 + 手工 `tail` | 结构化存储 + 查询 + 关联 + 案件 |
| 跨源关联（EDR/Suricata/WAF）靠人工对比 | 统一时间线与关联规则，支持外部告警注入 |
| 报告由 `edrctl report generate` 单机生成 | 中心侧跨主机攻击链还原 |
| anchor 概念存在但控制面未接线 | anchor 汇聚是中心的**核心职责** |
| Web 仪表盘被移除（怕攻击面） | CLI 优先，Web 作为独立可选组件并强隔离 |

---

## 2. 拓扑与数据流

```
   各主机 Agent                            审计运营中心
┌────────────────┐                    ┌───────────────────────────────┐
│ event + chain  │── mTLS/签名事件 ──▶│ ingest (认证/去重/校验)        │
│ anchor(本地)   │── 链头 anchor ────▶│ trust (锚定/跨主机链校验)      │
│ respond ◀──────│◀─ 处置命令(审批) ──│ orchestrate                    │
└────────────────┘                    │        │                       │
                                      │        ▼                       │
                                      │      store (追加式)            │
                                      │        │                       │
                                      │        ▼                       │
       外部源                          │ correlate (关联/ATT&CK/基线)    │
┌──────────────┐                      │        │                       │
│ Suricata/WAF │── 告警注入 ─────────▶│      cases (案件/时间线)        │
│ SIEM/SOAR    │◀─ 导出(CEF/LEEF) ────│      report / export            │
└──────────────┘                      │      ui (CLI/Web)              │
                                      └───────────────────────────────┘
```

**双通道设计**：控制命令（下发处置）与事件上报分离；上报可批量、可重放幂等；命令必须
审批并全程审计。

---

## 3. 数据模型（中心侧）

| 实体 | 关键字段 | 说明 |
|------|----------|------|
| `Host` | host_id, boot_id, hostname, agent_version, first/last_seen | 以 `host::boot_id` 为主键避免 DHCP/重启混淆 |
| `Agent` | agent_id, host_id, capabilities{}, enforcement_layers{} | 上报自身能力与**实际生效的强制层**（含 LSM 是否可用） |
| `Event` | event_id, chain{chain_id,seq,prev_hash,hash,hmac}, ts, category, severity, subject, object, rule_ids[] | 与 agent 侧 `internal/event` 同构 + 中心扩展 |
| `Alert` | alert_id, host_id, rule_id, severity, decision, ts, event_refs[] | 规则命中/关联产出 |
| `Case` | case_id, title, status, severity, hosts[], alerts[], timeline[], disposition | 研判单元 |
| `Indicator` | ioc, type(ip/domain/hash/path), source, confidence, ttl | IOC 库（可对接威胁情报） |
| `Action` | action_id, case_id, host_id, action, request, approver, result, ts | 处置编排记录 |
| `Anchor` | host_id, chain_id, seq, hash, hmac, received_at | 信任锚 |

**设计取舍**：事件先以 **JSONL/列式（Parquet）** 落地，查询用 **SQLite（起步）**，
数据量上来后平滑切 **ClickHouse**。不引入重型依赖，保持"轻量、可离线"的基因。

---

## 4. 接入与信任

1. **传输**：agent → center 走 mTLS（或复用 HMAC 签名，二者任选其一，配置强制非空）。
2. **事件签名**：每条事件可携带 agent 私钥签名（Ed25519）；中心用预置公钥验证 → 防伪造来源。
3. **链校验**：中心对每台主机的 `seq` 连续性与 `prev_hash` 链做**独立重放校验**，
   并与 agent 上报的 anchor 比对 → 检测：
   - 主机侧日志被删除/截断（anchor.seq > 收到的事件 seq）
   - 主机侧被篡改（同 seq 不同 hash）
   - 链被重置（chain_id 变化无对应重启事件）
4. **幂等**：以 `(host_id, chain_id, seq)` 去重，支持重放与断点续传。

> 这解决了旧项目"anchor 传 nil、链可降级"的核心缺陷：**中心成为不可自证的信任锚**。

---

## 5. 关联分析（中心的增值核心）

### 5.1 关联维度

| 类型 | 规则示例 |
|------|----------|
| 同主机攻击链 | 下载 → 落盘 → 赋权 → 执行 → 外联，在时间窗 + 同 PID/父子关系内串联 |
| 跨主机横向 | A 主机出现 SSH 隧道进程，B 主机同期出现 `authorized_keys` 写入 |
| 与网络侧对齐 | EDR 的 `connect` 目的地址 ∩ Suricata/WAF 告警的源/目的 → 同一攻击者 |
| 失陷指标 | IOC 命中（恶意 IP/域名/文件哈希） |
| 异常基线 | 进程创建频率、外联频率（beacon 周期）、非工作时间行为 |
| ATT&CK 映射 | 规则带 `technique_id`，案件自动聚合战术阶段 |

### 5.2 关联引擎

- 起步：**规则化关联**（时间窗 + 实体一致 + 规则序列），可解释、可单测。
- 进阶：**行为序列**（A→B→C within Ns）与**状态机**，最终可评估引入 Sigma 转译。
- 与之对立：**降噪**（抑制、同源归并、按案件合并），避免告警疲劳。
- 关联产出 `Case`，并给每条 `Alert` 打 ATT&CK 战术/技术标签。

### 5.3 时间与上下文

- 统一时间基准（事件自带 `time`，中心做时钟偏移估计并矫正展示，不改原始值）。
- 任何关联结论必须**可回溯到原始事件**（case.timeline 指向 event_id）。

---

## 6. 案件管理与运营流程（SOP）

```
接入事件 → 规则/关联 → 告警 → (降噪) → 案件
                                     │
              ┌──────────────────────┴──────────────────────┐
              ▼                                              ▼
        人工研判 (CLI)                                  自动处置(可选)
   收录证据 / 标记 IOC / 判定真伪                  命中高危规则 → 隔离/斩杀
              │                                      （需审批或明确授权）
              ▼
        处置结论 (true_positive / false_positive / benign)
              ▼
        报告生成 + 复盘 + 规则调优
```

- **案件状态机**：`new → triage → investigating → contained → closed`。
- **证据不可变**：案件引用的事件/文件哈希只读；导出带链校验。
- **闭环**：误报要能回流为策略调整（白名单/阈值），形成"检测→研判→调优"环路。

---

## 7. 处置编排

- 中心下发命令（kill/kill_tree/quarantine/isolate/suspend）→ agent 执行 → 结果回传。
- **审批边界**：高危动作（隔离主机、斩杀系统进程）需显式审批或预授权令牌。
- **全部审计**：命令请求人、审批人、目标、结果、时间写入链。
- **回滚**：网络隔离/文件隔离保留快照与超时回滚（沿用 agent 侧能力）。
- **fail-safe**：命令通道不可达时，agent 保持本地既定策略，不受中心宕机影响。

---

## 8. 报告与导出

| 输出 | 用途 |
|------|------|
| 事件报告（Markdown/PDF） | 总览 / 按主机 / 按规则 / 时间线 / 攻击链 / 响应 / 完整性 |
| SIEM 导出 | CEF / LEEF / OTLP |
| 合规报表 | 链完整性、策略版本、处置留痕 |
| 机器可读 | JSON（供 SOAR/SIEM 二次处理） |

---

## 9. UI 与 CLI

- **CLI 优先**（`edrctl` 连接中心）：`cases ls/show/disposition`、`events query`、
  `hosts ls`、`policy push`、`action run`。
- **Web**：作为**独立可选组件**，与中心进程隔离（单独端口、只读默认、认证前置），
  改掉旧项目"Web 与 agent 同进程"的高攻击面。

---

## 10. 部署形态与安全边界

| 形态 | 说明 |
|------|------|
| 单机中心 | 一台 server，内网，最小可用 |
| HA 中心 | Active/Standby + 共享存储/复制；沿用 `lease/liveness` 思路 |
| 中心自身安全 | 最小权限、只监听内网、mTLS、独立加固、只读默认；中心失守不应导致全网 agent 被控 |

**信任边界原则**：中心能给 agent 下发**处置命令**，但**不能下发任意代码/任意命令**；
命令是封闭枚举（与 agent 响应动作一致），杜绝"中心被攻破 → 全网 RCE"。

---

## 11. 分阶段落地（M8.x）

| 子阶段 | 交付 | 验收 |
|:---:|------|------|
| M8.0 | 接入认证 + 存储 + `events/hosts` 查询 | 多机事件入库；幂等重放；链完整性校验通过 |
| M8.1 | 关联引擎（规则化）+ ATT&CK 标签 | 攻击链还原用例；误报样本 |
| M8.2 | 案件 + CLI 研判 | 案件状态机；证据回溯到 event_id |
| M8.3 | 处置编排 + 审批 + 审计 | 命令下发/回执；未授权被拒 |
| M8.4 | 报告 + SIEM 导出 | CEF/LEEF 校验 |
| M8.5 | HA 中心 | 主备切换演练 |
| M8.6 | Web（可选、隔离） | 认证/只读/攻击面评审 |

---

## 12. 与外部系统集成点

| 系统 | 方向 | 方式 |
|------|------|------|
| Suricata | 入 | 读取 `eve.json` / 接收告警（网络侧） |
| WAF | 入 | 读取拦截日志 |
| SIEM | 出 | CEF/LEEF/OTLP |
| SOAR | 出/入 | JSON + 处置命令回执 |
| 威胁情报 | 入 | IOC 拉取，写入 `Indicator` |

---

## 13. 待评审的关键取舍

1. **存储起点**：SQLite/Parquet（轻量）优先，还是直接上 ClickHouse？
2. **事件签名**：每条事件 Ed25519 签名（强，成本高） vs 仅链 HMAC + 中心侧链校验（够用）？
3. **关联范围**：M8 只做规则化关联，还是直接规划序列/状态机？
4. **Web**：是否需要，还是长期只保留 CLI？
5. **中心职责边界**：是否接受"命令封闭枚举、不下发任意命令"这一安全约束？
