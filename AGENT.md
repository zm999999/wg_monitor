# AGENT.md — 面向 AI Agent / 协作者的开发指引

本项目是一个运行在 **Windows (amd64)** 上的 WireGuard VPN 自动监控与自愈 **Windows Service**，由 Go 编写。本文件说明项目结构、关键约定、如何构建/测试，以及修改代码时需要注意的边界条件。修改任何文件前请先读完。

---

## 1. 项目目标（一句话）

长期后台运行，监控本机 WireGuard Tunnel 状态与 VPN 内网连通性；出现异常时按 **「重启 WireGuard → 重启网卡 → 重启电脑」** 分级策略自愈，而非一出问题就重启机器。核心是**稳定、低资源、长期运行**。

---

## 2. 构建、测试、运行

> 目标平台 Windows/amd64。**所有真实 OS 调用（SCM、wg.exe、PowerShell、shutdown、Event Log）只在 `windows` build tag 下编译**，请在本机 Windows 上构建，或交叉编译：

```powershell
# 本机 Windows
go build -o wg-monitor.exe .
go test ./...

# 交叉编译（在任意平台）
set GOOS=windows
set GOARCH=amd64
go build -o wg-monitor.exe .
```

注意：
- `cmd/service.go` 无条件引用 `logger.InstallEventSource`，而该函数仅在 `logger/winevent_windows.go`（`//go:build windows`）中实现。**在非 Windows 平台直接 `go build ./...` 会失败**——这是设计使然，请用上述交叉编译方式。
- 本机若没有 gcc，`go test -race` 需要 CGO 会失败；并发安全靠 `sync.Mutex` 单飞（single-flight）保证，不依赖 `-race`。
- 依赖固定：`golang.org/x/sys v0.26.0`、`gopkg.in/yaml.v3 v3.0.1`。模块代理建议 `https://goproxy.cn,direct`。

子命令：
```
wg-monitor.exe install | uninstall | start | stop | status
wg-monitor.exe run          # 前台调试（不注册服务）
wg-monitor.exe check        # 一次性健康检查并打印摘要
wg-monitor.exe version
```

---

## 3. 架构与包职责（职责分离，禁止把逻辑堆进 main）

| 包 / 文件 | 职责 | 是否含 OS 调用 |
|---|---|---|
| `main.go` | 子命令分发；`svc.IsWindowsService()` 为真则走 `cmd.runService` | 仅分发 |
| `cmd/service.go` | Windows Service 注册/控制、`svc.Handler` 优雅停止、Event Log 源安装 | 是（SCM、Event Log） |
| `config/` | YAML 解析、`config.Duration`（支持 `"180s"/"30m"`）、默认值、校验 | 否 |
| `logger/` | 滚动文件日志（级别过滤 + 文件轮转） | 否 |
| `logger/winevent_windows.go` | Windows Event Log 写入（`//go:build windows`） | 是（Event Log） |
| `monitor/` | **核心**：检测只检测、恢复只恢复；状态机 + 单飞 | 否（只依赖接口） |
| `wireguard/` | `Controller` 接口 + Windows 实现（SCM 控制/重启）+ `wg.exe` 解析（纯函数） | 是（SCM、wg.exe） |
| `network/` | `TargetChecker`（TCP/ICMP 探测）+ `Controller`（网卡 Disable/Enable） | 是（PowerShell） |
| `system/` | `Controller`（电脑重启）+ `RebootTracker`（防无限重启，持久化 JSON） | 是（shutdown） |

**检测与恢复分离**是铁律：`HealthChecker.Check()` 只产出 `HealthResult`，绝不直接调用重启；恢复由 `RecoveryManager` 单独驱动。

---

## 4. 关键接口（OS 耦合点都收口在接口里，便于 mock 测试）

所有真实 Windows 能力都通过以下接口注入，`monitor` 包只依赖接口，因此可以脱离 Windows 单测：

```go
// wireguard/service.go
type Controller interface {
    ServiceStatus(ctx context.Context) (ServiceState, error)
    RestartTunnel(ctx context.Context) error
    TunnelStatus(ctx context.Context) (*TunnelStatus, error)
}

// network/adapter.go
type Controller interface {
    RestartAdapter(ctx context.Context) error
}

// network/connectivity.go
type TargetChecker interface {
    Check(ctx context.Context, t Target) (ok bool, latency time.Duration, err error)
}

// system/reboot.go
type Controller interface {
    RestartComputer(ctx context.Context) error
}
```

**新增一个 OS 能力或修改某层默认实现时：先改接口、再写 Windows 实现、再用 mock 补测试，不要让 `monitor` 直接 import `golang.org/x/sys`。**

---

## 5. 状态机与恢复流程（修改恢复逻辑的唯一正确位置）

- 枚举见 `monitor/state.go`：`RecoveryLevel`（Healthy→RestartWireGuard→RestartNetwork→RestartComputer）与上报用的 `HealthState`（Healthy/Degraded/WG_RESTART/NETWORK_RESTART/COMPUTER_RESTART）。
- 决策核心在 `monitor/recovery.go`：
  - `levelForDuration(d)` 把「异常持续时长」映射到目标级别（阈值 `wg_restart_after ≤ network_restart_after ≤ computer_restart_after`）。
  - `Process()` 每周期调用，但受两道闸门保护：**单飞**（`rm.active` + `sync.Mutex`，同一时刻只跑一个恢复动作）和 **`recovery_cooldown`**（上次动作后至少冷却 N 秒）。
  - 次数上限 `MaxWGRestart`/`MaxNetworkRestart` 用尽后**自动升级**到下一档（不立即重启电脑）。
  - 触发 `restart_computer` 前必过 `RebootTracker.CanReboot()`：`MaxRebootPerHour` + `RebootCooldown` 双重防护，重启记录写入 `state/reboots.json`，**跨重启生效，防止开机即重启的死循环**。
  - 恢复成功（下一次 `Healthy=true`）会 `resetLocked()`：清空 `unhealthySince`、计数、`currentLevel`。注意它**故意保留** `lastActionAt` 与 `active`，让冷却与在途动作自然收尾。

**不要在 `check()` 或别处写 `if !healthy { restart() }` 式直连逻辑。**所有恢复触发只走 `RecoveryManager.Process`。

---

## 6. 配置约定（禁止硬编码任何可调参数）

- 全部参数来自 YAML（`config.yaml.example` 是权威模板）。解析见 `config/config.go`，`config.Duration` 支持 `"180s"`/`"30m"`。
- `config.Load(path)` = 默认值 → 合并文件 → `Validate()`。新增配置项时：在对应 struct 加字段 + 在 `DefaultConfig()` 给默认值 + 必要时在 `Validate()` 加不变量（如阈值单调、端口范围）。
- 禁止硬编码的量：检测周期、handshake 超时、VPN 目标、网卡名、WG 服务名、各档阈值、重启次数、cooldown、日志路径、StateDir。
- 路径约定：`C:\ProgramData\WGMonitor\config.yaml`、`...\logs\monitor.log`、`...\state\reboots.json`。

---

## 7. 测试约定

- 测试全部用 `monitor/mocks_test.go` 里的 mock（`mockWG`/`mockNet`/`mockSys`/`mockTargetChecker`）实现接口，**绝不触发真实 Windows 调用**。
- 覆盖重点：`TestHealthy`、`TestTransientFailure`、`TestWireGuardRecovery`、`TestNetworkRecovery`、`TestRebootLimit`、`TestRecoveryCooldown`、`TestStartupGracePeriod`，以及 `wireguard/status_test.go`（`wg.exe` 输出解析纯函数）、`config/config_test.go`（解析/校验/默认值）、`logger/logger_test.go`（轮转/级别过滤）。
- 加测试时优先 mock 而非改真实实现；真实实现的外部命令必须 `context.WithTimeout` 包裹（见各层 `DefaultTimeouts`）。

---

## 8. 修改代码时的硬性约束（容易踩坑）

1. **优雅停止**：`cmd/service.go` 收到 `Stop/Shutdown` 时 cancel context → 等 `monitor.done` → 退出。恢复动作在自身 ctx 下跑完，不留 `wg.exe`/`powershell.exe` 孤儿进程。改动停止逻辑时务必验证无孤儿进程。
2. **开机 Grace Period**：`Monitor.graceUntil` 期间只记录、不恢复；不要在 grace 期内触发任何重启。新增启动期逻辑要尊重该窗口。
3. **瞬时抖动不误判**：仅当 VPN 内网目标（`min_success_targets` 个成功）不可达才判异常；`handshake` 过期但无流量不算故障。改健康判定时不要退化为「无 handshake 即故障」。
4. **单飞**：恢复期间普通 `Process` 仍记录健康检查，但不开新动作。任何新增恢复动作都要走 `dispatchLocked` + goroutine + 收尾 `rm.active=false`。
5. **所有外部操作加超时**：wg.exe 10s、Service stop 15s、start 30s、TCP 5s、PowerShell 30s，统一 `context.WithTimeout`。
6. **网络恢复用 Disable/Enable-NetAdapter，不要用 `ipconfig /release|renew`**（会影响 DHCP/路由）。
7. **权限**：安装服务需 LocalSystem/管理员；Event Log 源安装需管理员。不要为方便扩大权限。
8. **Windows-only build tag**：任何 `golang.org/x/sys` 调用放 `//go:build windows` 文件，并确认非 Windows 平台有 stub 或该符号不被无条件引用（当前 `InstallEventSource` 仅 Windows 有，故交叉编译而非裸 `go build ./...`）。

---

## 9. 常见任务入口

| 任务 | 看哪里 |
|---|---|
| 改检测频率/健康策略 | `config` + `monitor/health.go` |
| 改恢复阈值/升级链 | `config.RecoveryConfig` + `monitor/recovery.go` |
| 改 WG 服务/隧道解析 | `wireguard/service.go`、`wireguard/status.go` |
| 改网卡重启方式 | `network/adapter.go` |
| 改连通性探测（TCP/ICMP） | `network/connectivity.go` |
| 改防无限重启策略 | `system/reboot.go`（RebootTracker） |
| 改日志/Event Log | `logger/logger.go`、`logger/winevent_windows.go` |
| 改 Service 安装/启停 | `cmd/service.go` |
| 改 CLI 分发 | `main.go` |

---

## 10. 验收速查

- 正常：`WireGuard Running` + handshake 正常 + VPN 目标通 → 不执行任何恢复。
- WG Service 停/隧道 handshake 超时且 VPN 不通 → 持续超 `wg_restart_after` → 重启 WG（×`MaxWGRestart`）→ 不行则网卡（×`MaxNetworkRestart`）→ 不行且超 `computer_restart_after` 且未触发重启上限 → 重启电脑。
- 1 小时内已重启过 → `AUTO_REBOOT_BLOCKED`，记录原因，不死循环。
- 全绿标准：`go build` 通过、`go vet ./...` 通过、`go test ./...` 通过。
