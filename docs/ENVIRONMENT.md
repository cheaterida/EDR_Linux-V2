# 目标环境与能力探测（测试机）

> 主机：`lcz@192.168.214.144`（内网测试机）
> 探测日期：2026-10-11（只读命令）

## 1. 主机画像

| 项 | 值 |
|----|----|
| 发行版 | Ubuntu 24.04.2 LTS |
| 内核 | 6.17.0-23-generic（HWE，x86_64） |
| cgroup | cgroup v2（`cgroup2fs`） |
| BTF | `/sys/kernel/btf/vmlinux` 存在（6.9 MB） |
| 挂载 | `securityfs` ✓、`bpf` fs（`/sys/fs/bpf`，mode=700）✓ |
| 非特权 BPF | `unprivileged_bpf_disabled=2`（完全禁用，仅 root） |
| 现有 EDR | 无（`/opt/edr`、`/etc/edr` 均不存在） |

工具链：

| 工具 | 版本 |
|------|------|
| clang | 18.1.3 |
| bpftool | 已安装 |
| gcc | 已安装 |
| go | 系统 `/usr/bin/go` |
| libbpf-dev | 1.3.0 |
| libelf-dev | 0.190 |

`lcz` 属于 `sudo` 组，`sudo`（口令同 SSH）可用 → BPF 加载以 root 执行。

## 2. 内核编译选项

```
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_BPF_KPROBE_OVERRIDE=y      ← kprobe override 可用
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

## 3. 关键结论：BPF LSM 未激活

```
/sys/kernel/security/lsm =
  lockdown,capability,landlock,yama,apparmor,ima,evm
```

- `CONFIG_BPF_LSM=y` **仅表示内核支持**；当前 LSM 顺序里**没有 `bpf`**。
- Ubuntu + AppArmor 默认不启用 BPF LSM，必须在启动参数加入
  `lsm=lockdown,capability,landlock,yama,apparmor,bpf`（GRUB `GRUB_CMDLINE_LINUX`）后重启。
- 未加入前，`bpf_program__attach_lsm()` / `link.AttachLSM()` 会失败。

> **对旧项目的映射**：旧项目把 `lsm_selfprotect.bpf.c` 标为"主阻断路径"。在这台
> 机器上该路径根本挂不上——这正是旧项目"宣称 ≠ 现实"的一个具体来源。

## 4. 由此确定 v2 的强制（enforcement）策略

强制层必须"运行时可探测 + 可降级"，不能硬依赖 LSM：

| 层 | 机制 | 本机可用性 | 定位 |
|----|------|:---:|------|
| syscall 拒绝 | **kprobe override**（`bpf_override_return`） | ✅ | **主路径**（kill/ptrace/pidfd_send_signal/bpf/module） |
| 文件访问 | fanotify `FAN_OPEN_PERM` | ✅ | 主路径（同步 deny） |
| 网络 | nftables（用户态）| ✅ | 主路径；ring0 断线为增强 |
| 进程信号/权限 | BPF LSM（task_kill/ptrace_access_check/security_bpf） | ❌（需 GRUB 开启） | **可选增强**，探测到 `bpf` 才用 |
| 自保护对象识别 | own_bpf_objs + kprobe bpf() 拦截 | ✅ | 主路径（不依赖 LSM） |

**设计约束（写入 MODULES/PLAN）**：

1. `internal/protect` 启动时探测 `/sys/kernel/security/lsm` 是否含 `bpf`，并把结果写入
   能力矩阵与 `/health`；LSM 缺失时自动降级为 kprobe 主路径，**不静默失败**。
2. 提供 preflight 检查脚本/命令，输出"如何开启 BPF LSM"（GRUB 修改指引）。
3. 能力矩阵新增条目 `enforcement_lsm_available`：本机预期为 **FAIL/NA**（诚实反映），
   而不是像旧项目那样把它当成"已生效"。

## 5. 其他部署前提

- 需要 root（或用 `setcap cap_bpf,cap_perfmon,cap_sys_admin+ep` 最小化）。
- fanotify 需要 `CAP_SYS_ADMIN`；systemd 单元需放行 `fanotify_init/fanotify_mark`。
- kprobe 符号占用：加载前检查是否有其它 BPF 程序占用同名探针符号。
- `unprivileged_bpf_disabled=2` 是好基线，保持不要放开。
