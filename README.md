# wg-monitor — WireGuard VPN 自动监控与自愈 Windows Service

`wg-monitor` 是一个用 Go 编写的 Windows 服务，长期在后台监控本机 WireGuard 隧道状态与 VPN
内网连通性。当异常发生时，它按 **轻量恢复 → 网络恢复 → 系统重启** 的分级策略自动自愈。

---

## 一、概述

### 1.1 特性

- 监控 WireGuard Windows 服务（`WireGuardTunnel$<name>`）运行状态
- 解析 `wg.exe` 输出，判断 `latest handshake` 是否过期
- 探测多个 VPN 内网目标（TCP 优先，兼容 ICMP），至少一个可达即视为 VPN 可用
- 统一健康模型 `HealthResult`，不依赖单一指标判断
- 状态机驱动的逐级恢复：`Healthy → RestartWireGuard → RestartNetwork → RestartComputer`
- 防瞬时抖动：连续失败 + 持续时长阈值才触发恢复
- 防无限重启：每小时重启次数上限 + 重启冷却（持久化到磁盘，跨重启生效）
- 单飞（single-flight）恢复，恢复期间仍持续记录健康检查
- 开机 Grace Period，避免 Windows 启动未完成就误恢复
- 滚动文件日志 + 可选 Windows Event Log
- 作为 Windows Service 运行，支持开机自启

### 1.2 工作原理

程序每 `health.interval`（默认 10s）执行一次健康检查，产出 `HealthResult`。只有
**VPN 内网目标不可达**才判定异常（即使 `handshake` 过期，只要 VPN 仍可访问就不动作——
避免无业务流量时的误判）。异常按"持续时长 + 各档阈值"驱动状态机逐级升级恢复：

```
HEALTHY
  │ 连续失败且持续 ≥ wg_restart_after (默认30s)
  ▼
RESTART_WIREGUARD        → 重启 WireGuard 隧道服务（最多 max_wg_restart 次）
  │ 仍异常且持续 ≥ network_restart_after (默认90s)
  ▼
RESTART_NETWORK          → 禁用/启用网络适配器（最多 max_network_restart 次）
  │ 仍异常且持续 ≥ computer_restart_after (默认180s)
  ▼
RESTART_COMPUTER         → 重启电脑（受 max_reboot_per_hour + reboot_cooldown 保护）
```

- 恢复成功后清空故障计时器与连续失败计数，并进入 `recovery_cooldown` 稳定观察后才允许
  下一次恢复。
- 任一档重试次数耗尽自动升级到下一档。
- 重启电脑前校验 `max_reboot_per_hour` 与 `reboot_cooldown`；若已达上限则记录
  `AUTO_REBOOT_BLOCKED` 并放弃本次重启，避免无限重启循环。
- 所有恢复动作均为 single-flight：同一时刻仅一个恢复在运行，期间仍持续记录健康检查。

### 1.3 目录结构

```
wg-monitor/
├── main.go                # CLI 分发：install/uninstall/start/stop/status/run/check/version
├── go.mod
├── config.yaml.example    # 生产配置示例（完整注释）
├── config.minimal.yaml     # 最小可运行配置（仅必填项）
├── README.md
├── cmd/service.go         # Windows Service 注册/控制 + svc.Handler
├── config/config.go       # YAML 配置解析、校验、默认值
├── logger/logger.go       # 滚动文件日志 + EventLog 抽象
├── monitor/
│   ├── health.go          # HealthChecker（检测，不做恢复）
│   ├── state.go           # RecoveryLevel / HealthState 枚举
│   ├── recovery.go        # RecoveryManager（状态机 + single-flight）
│   ├── monitor.go         # 监控循环
│   └── compose.go         # 依赖装配
├── wireguard/
│   ├── service.go         # WireGuard Controller（Service/Tunnel/重启）
│   └── status.go          # wg.exe 输出解析（纯函数，可测）
├── network/
│   ├── connectivity.go    # TCP/ICMP 目标探测
│   └── adapter.go         # 网卡禁用/启用
└── system/reboot.go       # 电脑重启 + 防无限重启记录
```

---

## 二、启动（部署与运维）

### 2.1 配置

复制示例并按实际环境修改：

```powershell
Copy-Item config.yaml.example C:\ProgramData\WGMonitor\config.yaml
# 用编辑器修改 service_name / interface_name / targets / adapter_name / logging.file / windows.state_dir 等
# 注意：配置文件不会自动被发现，需放在 exe 同目录、设置 WGMONITOR_CONFIG，
# 或在 install / run / check 时携带 -config 指向该文件。
```

仓库另提供 `config.minimal.yaml`，仅含必填项、其余使用内置默认值，可作为最小可运行样例：

```powershell
Copy-Item config.minimal.yaml C:\ProgramData\WGMonitor\config.yaml
```

关键参数：

| 参数 | 必填 | 说明（括号内为默认值） |
| --- | --- | --- |
| `wireguard.service_name` | 是 | WireGuard 隧道服务名，通常 `WireGuardTunnel$<name>` |
| `wireguard.interface_name` | 是 | WireGuard 接口名 |
| `wireguard.handshake_timeout` | 否 | handshake 最大允许年龄（默认 `180s`） |
| `wireguard.wg_executable` | 否 | wg.exe 路径（默认 `wg.exe`，按 PATH 查找） |
| `health.interval` | 否 | 健康检查周期（默认 `10s`） |
| `health.startup_grace_period` | 否 | 开机后多久内禁止自动恢复（默认 `120s`） |
| `health.min_success_targets` | 否 | VPN 视为可用所需的最少可达目标数（默认 `1`） |
| `targets` | 是 | VPN 内网探测目标（建议 ≥ 2） |
| `network.adapter_name` | 是 | 二级恢复重启的网卡名 |
| `recovery.wg_restart_after` | 否 | 持续异常多久后重启 WireGuard（默认 `30s`） |
| `recovery.network_restart_after` | 否 | 持续异常多久后重启网卡（默认 `90s`） |
| `recovery.computer_restart_after` | 否 | 持续异常多久后重启电脑（默认 `180s`） |
| `recovery.wg_restart_wait` | 否 | WireGuard 重启后等待初始化（默认 `10s`） |
| `recovery.network_restart_wait` | 否 | 网卡重启后等待恢复（默认 `15s`） |
| `recovery.max_wg_restart` / `max_network_restart` | 否 | 每级最大重试次数（默认 `3` / `2`） |
| `recovery.max_reboot_per_hour` | 否 | 每小时自动重启上限（默认 `1`） |
| `recovery.reboot_cooldown` | 否 | 两次重启最小间隔（默认 `30m`） |
| `recovery.recovery_cooldown` | 否 | 任意恢复后稳定观察时间（默认 `60s`） |
| `logging.level` | 否 | 日志级别 DEBUG/INFO/WARN/ERROR（默认 `INFO`） |
| `logging.file` | 是 | 日志文件路径 |
| `logging.max_size_mb` | 否 | 单文件轮转大小 MB（默认 `50`） |
| `logging.max_backups` | 否 | 保留备份份数（默认 `5`） |
| `windows.service_name` | 否 | 注册的 Windows 服务名（默认 `WGMonitor`） |
| `windows.event_source` | 否 | Windows Event Log 源名（默认 `WGMonitor`） |
| `windows.state_dir` | 是 | 跨重启状态（重启记录）目录 |

> 标注「必填」的参数为空时配置校验会直接报错；其余参数省略即使用上表括号内的默认值。

#### 配置文件查找优先级

程序按以下顺序查找 `config.yaml`，**命中第一个存在的即使用**：

| 优先级 | 来源 | 说明 |
| --- | --- | --- |
| 1 | `-config <path>` / `-config=<path>` 命令行参数 | 运行时显式指定；`install` 时若携带该参数，会被写入服务命令行的 `BinaryPathName`，服务启动后自动生效 |
| 2 | 环境变量 `WGMONITOR_CONFIG` | 适合用环境变量统一注入路径 |
| 3 | **exe 同目录下的 `config.yaml`** | 用 `os.Executable()` 定位 exe 所在目录后拼接，与进程工作目录无关（Windows 服务的工作目录是 `C:\Windows\System32`，但此规则仍能正确命中） |

**三处均未找到配置文件时，程序直接报错退出并提示如何指定配置，不会静默回退到任何硬编码路径。**

> 建议：将 `config.yaml` 放在 exe 同目录，或在 `install` / `run` / `check` 时显式携带 `-config <path>`（安装时会写入服务命令行，服务启动后自动生效）；也可通过环境变量 `WGMONITOR_CONFIG` 注入。若 `install` 时未带 `-config` 且 exe 同目录也没有 `config.yaml`，服务会因找不到配置而无法启动——务必确认配置可达。

### 2.2 安装

需 **管理员** 权限（用于注册服务、控制 WireGuard 服务、禁用/启用网卡、调用 shutdown）。

```powershell
# 注册为自动启动服务，并安装 Event Log 源（建议显式指定 -config）
wg-monitor.exe install -config C:\ProgramData\WGMonitor\config.yaml
wg-monitor.exe start
```

> 说明：`install` 时携带的 `-config` 会被写入服务命令行，服务启动后自动生效。若未带 `-config` 且 exe 同目录也没有 `config.yaml`，服务会因找不到配置而无法启动——务必确认配置可达。

### 2.3 卸载

```powershell
wg-monitor.exe stop
wg-monitor.exe uninstall
```

### 2.4 启动 / 停止

```powershell
wg-monitor.exe start
wg-monitor.exe stop
wg-monitor.exe status        # 显示服务状态
```

### 2.5 前台调试

`run` 模式不注册服务，直接在控制台运行并输出日志，按 `Ctrl+C` 退出：

```powershell
wg-monitor.exe run
wg-monitor.exe run -config C:\path\to\config.yaml
```

### 2.6 一次性健康检查

`check` 仅执行一次探测并打印结果，返回码 0=健康 / 1=异常：

```powershell
wg-monitor.exe check
# 输出示例：
# WireGuard Service : RUNNING
# Handshake Age     : 12s
# Internet          : OK
# VPN Target        : OK
# Overall           : HEALTHY
```

### 2.7 日志

- 文件：`C:\ProgramData\WGMonitor\logs\monitor.log`（按大小轮转，保留 `max_backups` 份）
- 格式：`2026-09-30 12:00:10 INFO  health check service=running handshake_age=12s vpn=healthy`
- 重要事件同时写入 **Windows Event Log**（源名 `WGMonitor`，需在 `install` 时注册）
- 跨重启的重启记录：`C:\ProgramData\WGMonitor\state\reboots.json`

### 2.8 权限要求

服务应以 **LocalSystem**（或具备以下权限的账户）运行：

- 启动/停止 WireGuard 隧道服务
- 禁用/启用网络适配器（`Disable-NetAdapter` / `Enable-NetAdapter`）
- 执行 `shutdown /r`

### 2.9 优雅停止

收到 `SERVICE_CONTROL_STOP` 时，服务取消监控 context、停止健康检查、等待正在执行的
恢复动作结束、关闭日志后退出，不残留 `wg.exe` / `powershell.exe` 孤儿进程。

### 2.10 常见问题

- **Q: 健康检查显示服务 `UNKNOWN`？** 服务名配置错误，或程序无权限查询 SCM。确认
  `wireguard.service_name` 与实际 `WireGuardTunnel$<name>` 一致。
- **Q: 为什么 handshake 过期但没恢复？** 若 VPN 内网目标仍可访问，`Healthy` 仍为 true；
  仅当 VPN 目标不可达时才触发恢复（避免无流量时的误判）。
- **Q: Event Log 里看不到事件？** 确认 `install` 时成功注册了事件源；若失败，日志仍写入文件。
- **Q: 重启电脑后立刻又重启？** `reboots.json` 已记录上次重启并在冷却/小时上限内阻止再次重启。
- **Q: `check` 提示 target 失败？** 确认目标 IP/端口在 VPN 内网可达，或改用 `icmp` 协议。

---

## 三、开发

### 3.1 编译

需要 Go 1.22+ 与目标为 Windows/amd64。

```powershell
# 在项目根目录
go build -o wg-monitor.exe .
```

交叉编译（在其它平台）：

```bash
set GOOS=windows
set GOARCH=amd64
go build -o wg-monitor.exe .
```

> 注意：`logger` 中部分实现带 `//go:build windows` 约束，裸 `go build ./...` 在非 Windows
> 平台会因缺少 Windows 专属符号而失败；跨平台编译请显式设置 `GOOS=windows GOARCH=amd64`。
> `go test -race` 需要 CGO（本机若无 gcc 则不可用），单飞安全性已通过 `sync.Mutex` 保证。

### 3.2 测试

```powershell
go test ./...      # 全部单元测试（状态机、解析、配置、防重启等，使用 mock，不触碰真实 Windows）
go vet ./...
go build ./...
```

单元测试覆盖：健康检查、失败计数、故障时长、Recovery Level 升级、冷却、最大重启次数、
配置解析、握手解析、启动 Grace Period、日志轮转/级别过滤。所有 Windows 能力（SCM、PowerShell、
`shutdown`、`wg.exe`）均通过接口隔离并以 mock 注入，测试环境不执行真实恢复动作。

### 3.3 包职责与分层

| 包 | 职责 | 是否含 OS 调用 |
| --- | --- | --- |
| `config` | YAML 解析、校验、默认值 | 否 |
| `logger` | 滚动文件日志 + EventLog 抽象 | 仅 `windows` 构建标签下 |
| `monitor` | 健康检测、状态机、恢复管理、循环 | 否（仅依赖接口） |
| `wireguard` | WG 服务/隧道查询、重启、`wg.exe` 解析 | 是（SCM / wg.exe） |
| `network` | TCP/ICMP 探测、网卡禁用/启用 | 是（PowerShell） |
| `system` | 电脑重启、防无限重启记录 | 是（shutdown / 文件） |
| `cmd` | Windows Service 注册/控制 + `svc.Handler` | 是（SCM） |
| `main` | CLI 子命令分发 | 否 |

核心原则：**检测与恢复分离**（`HealthChecker` 只产出 `HealthResult`，`RecoveryManager` 消费并恢复），
**状态机驱动**（不使用散落的 `if/else` 恢复链），**配置驱动**。

### 3.4 关键接口（可 Mock）

所有 Windows 能力通过接口收口，便于测试与替换实现：

```go
type Controller interface {        // wireguard.Controller
    ServiceStatus(ctx) (State, error)
    TunnelStatus(ctx) (*TunnelStatus, error)
    RestartTunnel(ctx) error
}
type Controller interface {        // network.Controller
    RestartAdapter(ctx) error
}
type TargetChecker interface {     // network.TargetChecker
    Check(ctx, target) (bool, error)
}
type Controller interface {        // system.Controller
    RestartComputer(ctx) error
}
```

`monitor` 层只依赖上述接口，不感知 Windows 实现；恢复逻辑唯一正确位置是
`monitor/recovery.go`（`levelForDuration` + single-flight + cooldown + 次数上限自动升级 +
`RebootTracker` 防无限重启）。

### 3.5 状态机与恢复流程

- 状态枚举见 `monitor/state.go`：`Healthy / RestartWireGuard / RestartNetwork / RestartComputer`。
- `RecoveryManager.Process(ctx, result)` 依据"异常持续时长"调用 `levelForDuration` 决定当前档位；
  恢复动作经 `sync.Mutex` + `active` 标志实现 single-flight，执行期间暂停新的恢复触发但仍记录健康检查。
- 恢复动作完成后等待对应 `wait`（`wg_restart_wait` / `network_restart_wait`）再释放 `active`，
  由下一个监控周期重新探测判断恢复是否成功。
- 防无限重启由 `system/reboot.go` 的 `RebootTracker` 负责：重启记录持久化到
  `windows.state_dir/reboots.json`，开机后据此判断是否在冷却/小时上限内。

### 3.6 修改硬性约束

- 恢复动作不得残留 `wg.exe` / `powershell.exe` 孤儿进程（优雅停止）。
- 开机 `startup_grace_period` 内禁止自动重启网络/电脑。
- 仅当 VPN 内网目标不可达才判异常，防止瞬时抖动误判。
- 所有外部操作（`wg.exe`、`Service stop/start`、TCP 探测、PowerShell）必须 `context.WithTimeout` 包裹，禁止无限阻塞。
- 网卡恢复用 `Disable-NetAdapter` / `Enable-NetAdapter`，**禁止** 使用 `ipconfig /release` + `/renew`。
- 恢复为 single-flight，同一时刻仅一个恢复动作运行。
- 配置参数禁止硬编码，统一来自 `config.yaml`。
- 安装/卸载/启动/停止均通过 exe 子命令完成；`install` 时 `-config` 写入服务命令行。

### 3.7 参考

更深入的架构、接口契约、状态机约束与"改什么看哪个文件"的任务入口表，见仓库内的
[`AGENT.md`](./AGENT.md)，供后续 Agent / 协作者开发时遵循。
