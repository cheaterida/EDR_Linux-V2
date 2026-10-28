# 功能测试（真机）

面向已安装 lab 的测试机，逐项验证 EDR 的采集/检测/强制/自保护/审计/控制面/运营中心/告警/rootkit/资源。
脚本以 **root** 运行（安装布局 `/opt/edr`、`/etc/edr`、`/run/edr`）。

## 前置

- 已执行 `scripts/install_lab.sh`（二进制、策略、admin key、center secret、systemd 单元）。
- root 权限；`bpftool`、`python3` 可用；`nft` 可用（nft 用例，缺失则 SKIP）。
- 可选：内核启用 BPF LSM（`lsm=...,bpf`）以验证 `--lsm`。
- 不要在自保护档用 `systemctl stop`/`kill` 停止 agent；脚本内部使用受控 `shutdown`。

## 脚本与覆盖

| 脚本 | 覆盖 |
|---|---|
| `ft1.sh` | 环境/安装；采集与 13 条检测规则；审计链校验与篡改检测；强制响应（kill / kill_tree / quarantine+restore / nft_block+rollback / fix_permissions / process_suspend）；控制面（非 root 拒绝 / token 防重放 / policy reload）；自保护（signal / pidfd / BPF map 守卫 / ATTACH 守卫 / LSM tkill / 哨兵）；稳定性与资源（drops、链续接） |
| `ft2.sh` | 运营中心闭环（hosts/events/correlations/cases/actions 编排/report/CEF）；告警渠道（webhook + 严重度过滤）；rootkit（干净主机无误报 + 空 proc-root 正向） |
| `resource.sh` | 稳态资源：20s 平均 CPU、RSS、drops、审计链校验 |

## 运行

```bash
scp test/functional/{ft1.sh,ft2.sh,resource.sh} lcz@HOST:/tmp/
ssh lcz@HOST 'sudo bash /tmp/ft1.sh'      # 约 60-90s
ssh lcz@HOST 'sudo bash /tmp/ft2.sh'      # 约 40-60s
ssh lcz@HOST 'sudo bash /tmp/resource.sh' # 约 35s
```

输出为 `PASS | 名称 | 证据` / `FAIL | ...` / `SKIP | ...`，末尾 `SUMMARY | PASS=.. FAIL=.. SKIP=..`。

## 最近一次结果（2026-10-17，Ubuntu 内核 7.0.0-38，BPF LSM 已启用）

- `ft1.sh`：**52 PASS / 0 FAIL / 2 SKIP**
- `ft2.sh`：**18 PASS / 0 FAIL / 0 SKIP**
- 合计：**70 PASS / 0 FAIL / 2 SKIP**
- `make gate` 绿；能力矩阵 **44/44**
- 稳态资源（`resource.sh`）：CPU ≈ **3.05%**（20s 平均），RSS ≈ **85–92MB**，`pipeline_dropped=0`、`bpf_dropped=0`
- 审计：`ok=true` + `anchor: consistent`

SKIP 说明：
- `HOST-MODULE-LOAD`：为避免在测试机加载内核模块，未主动触发（规则与探针已由能力测试覆盖）。
- `HOST-SEQ-DOWNLOAD-EXEC`：序列引擎由 `detect_sequence_fires` 能力测试覆盖。

## 已知测试边界

- 不执行 `network_isolate`（会切断 SSH）；`nft_block` 已覆盖。
- 强制动作需 agent 带 `--enforce`；nft 需 `--nft-enabled`；每个动作需**新 token**（防重放）。
- 自保护档必须走受控 `shutdown`；测试脚本已处理。
