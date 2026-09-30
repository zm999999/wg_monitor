// Command wg-monitor is a WireGuard VPN auto-monitor and self-healing Windows
// service. It can run as a service (launched by the SCM), in foreground debug
// mode (`run`), or as a one-shot probe (`check`).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"wg-monitor/cmd"
	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/monitor"

	"golang.org/x/sys/windows/svc"
)

const version = "1.0.0"

func main() {
	// When launched by the Service Control Manager, run as a service.
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runService()
		return
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("wg-monitor %s\n", version)
	case "install":
		must(cmd.InstallService(configArgFromOSArgs()))
	case "uninstall":
		must(cmd.UninstallService())
	case "start":
		must(cmd.StartService())
	case "stop":
		must(cmd.StopService())
	case "status":
		st, err := cmd.QueryStatus()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println("status:", st)
	case "run":
		runForeground()
	case "check":
		runCheck()
	default:
		usage()
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runService() {
	cfgPath, err := findConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	el := logger.OpenWindowsEventLog(cfg.Windows.EventSource)
	log, err := logger.New(logger.Options{
		Level:      logger.ParseLevel(cfg.Logging.Level),
		File:       cfg.Logging.File,
		MaxSizeMB:  cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
		EventLog:   el,
	})
	if err != nil {
		log = logger.NewStderr(logger.ParseLevel(cfg.Logging.Level))
		log.Errorf("file logger unavailable: %v", err)
	}
	defer log.Close()

	mon, _ := monitor.Compose(cfg, log)
	handler := cmd.NewServiceHandler(mon, log)
	log.Infof("service %s starting via SCM", cmd.ServiceName)
	if err := svc.Run(cmd.ServiceName, handler); err != nil {
		log.Errorf("svc.Run failed: %v", err)
		os.Exit(1)
	}
}

func runForeground() {
	cfg := loadOrExit()
	log := buildLogger(cfg, true)
	defer log.Close()

	mon, _ := monitor.Compose(cfg, log)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Infof("wg-monitor foreground mode (Ctrl+C to stop)")
	if err := mon.Run(ctx); err != nil {
		log.Errorf("monitor error: %v", err)
		os.Exit(1)
	}
}

func runCheck() {
	cfg := loadOrExit()
	log := buildLogger(cfg, false)
	defer log.Close()

	mon, _ := monitor.Compose(cfg, log)
	res := mon.Check(context.Background())
	fmt.Print(mon.Summary(res))
	if !res.Healthy {
		os.Exit(1)
	}
}

func loadOrExit() *config.Config {
	cfgPath, err := findConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	return cfg
}

func buildLogger(cfg *config.Config, stderr bool) *logger.Logger {
	el := logger.OpenWindowsEventLog(cfg.Windows.EventSource)
	log, err := logger.New(logger.Options{
		Level:      logger.ParseLevel(cfg.Logging.Level),
		File:       cfg.Logging.File,
		MaxSizeMB:  cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
		EventLog:   el,
		Stderr:     stderr,
	})
	if err != nil {
		log = logger.NewStderr(logger.ParseLevel(cfg.Logging.Level))
		log.Errorf("file logger unavailable: %v", err)
	}
	return log
}

// configArgFromOSArgs returns the explicit -config value from the command line
// (either "-config <path>" or "-config=<path>"), or "" if none was given. It
// does NOT apply the fallback resolution chain.
func configArgFromOSArgs() string {
	for i, a := range os.Args {
		if a == "-config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "-config="); ok {
			return v
		}
	}
	return ""
}

// findConfig resolves the configuration file path. It checks, in order:
//
//  1. the -config flag / -config= value from the command line
//  2. the WGMONITOR_CONFIG environment variable
//  3. a config.yaml located next to the executable
//
// The first candidate that exists on disk is returned. If none of them exist,
// it returns an error describing where it looked and how to provide a config —
// there is intentionally NO silent fallback to a hard-coded path.
func findConfig() (string, error) {
	type candidate struct {
		src, path string
	}
	var candidates []candidate
	if p := configArgFromOSArgs(); p != "" {
		candidates = append(candidates, candidate{"-config flag", p})
	}
	if p := os.Getenv("WGMONITOR_CONFIG"); p != "" {
		candidates = append(candidates, candidate{"WGMONITOR_CONFIG env", p})
	}
	if p, err := os.Executable(); err == nil {
		candidates = append(candidates, candidate{
			"config.yaml next to exe",
			filepath.Join(filepath.Dir(p), "config.yaml"),
		})
	}

	var missing []string
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			return c.path, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat config %s: %w", c.path, err)
		}
		missing = append(missing, fmt.Sprintf("  - %s  (%s)", c.path, c.src))
	}
	return "", fmt.Errorf("configuration file not found; searched:\n%s\n"+
		"provide it via -config <path>, set WGMONITOR_CONFIG, or place config.yaml next to the executable",
		strings.Join(missing, "\n"))
}

func usage() {
	fmt.Print(`wg-monitor ` + version + ` - WireGuard VPN auto-monitor & self-healing service

Usage:
  wg-monitor.exe install     Register the Windows service (auto-start)
  wg-monitor.exe uninstall   Remove the Windows service
  wg-monitor.exe start       Start the service
  wg-monitor.exe stop        Stop the service
  wg-monitor.exe status      Show service status
  wg-monitor.exe run         Run in foreground (debug)
  wg-monitor.exe check       One-shot health check and print result
  wg-monitor.exe version     Show version

Options:
  -config <path>   Override the configuration file path

Service account:
  The service must run as LocalSystem (or an account with rights to control the
  WireGuard service, disable/enable network adapters, and call shutdown).
`)
}
