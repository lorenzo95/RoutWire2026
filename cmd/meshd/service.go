package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	systemdUnitPath  = "/etc/systemd/system/meshd.service"
	sysvScriptPath   = "/etc/init.d/meshd"
	defaultSvcConfig = "/etc/meshd.yaml"
)

// checkServiceArgs validates the -service flag combination.
func checkServiceArgs(install, uninstall bool, system string) error {
	if !install && !uninstall {
		return fmt.Errorf("-service needs -install or -uninstall")
	}
	if install && uninstall {
		return fmt.Errorf("-install and -uninstall are mutually exclusive")
	}
	switch system {
	case "", "auto", "systemd", "sysvinit":
	default:
		return fmt.Errorf("-system must be auto, systemd, or sysvinit")
	}
	return nil
}

// detectInitSystem picks the service manager: systemd if it is demonstrably
// pid 1, sysvinit otherwise.
func detectInitSystem() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if b, err := os.ReadFile("/proc/1/comm"); err == nil && strings.TrimSpace(string(b)) == "systemd" {
		return "systemd"
	}
	return "sysvinit"
}

func systemdUnit(bin, conf string) string {
	return fmt.Sprintf(`[Unit]
Description=RoutWire mesh daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s -config %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, bin, conf)
}

func sysvScript(bin, conf string) string {
	return fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          meshd
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Routewire mesh daemon
# Description:       Decentralized WireGuard mesh daemon
### END INIT INFO

NAME=meshd
DAEMON=%s
CONFIG=%s
PIDFILE=/run/meshd.pid

is_running() {
	[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "$1" in
start)
	if is_running; then
		echo "$NAME already running"
		exit 0
	fi
	echo "Starting $NAME"
	if command -v start-stop-daemon >/dev/null 2>&1; then
		start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" --exec "$DAEMON" -- -config "$CONFIG"
	else
		nohup "$DAEMON" -config "$CONFIG" >>/var/log/meshd.log 2>&1 &
		echo $! >"$PIDFILE"
	fi
	;;
stop)
	if ! is_running; then
		rm -f "$PIDFILE"
		exit 0
	fi
	echo "Stopping $NAME"
	PID=$(cat "$PIDFILE")
	kill "$PID" 2>/dev/null
	i=0
	while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 20 ]; do
		sleep 0.5
		i=$((i + 1))
	done
	rm -f "$PIDFILE"
	;;
restart)
	"$0" stop
	"$0" start
	;;
status)
	if is_running; then
		echo "$NAME is running (pid $(cat "$PIDFILE"))"
	else
		echo "$NAME is not running"
		exit 1
	fi
	;;
*)
	echo "Usage: $0 {start|stop|restart|status}"
	exit 1
	;;
esac
`, bin, conf)
}

// runService handles `meshd service -install|-uninstall`.
func runService(configPath string, install, uninstall bool, system string) {
	if err := checkServiceArgs(install, uninstall, system); err != nil {
		fatalf("%v", err)
	}
	if os.Geteuid() != 0 {
		fatalf("managing the system service requires root (use sudo)")
	}

	bin, err := os.Executable()
	if err != nil {
		fatalf("resolve binary: %v", err)
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		fatalf("resolve binary: %v", err)
	}
	if configPath == "" {
		configPath = defaultSvcConfig
	}
	if install {
		if _, err := os.Stat(configPath); err != nil {
			fatalf("config %s not found — run 'sudo meshd init' first", configPath)
		}
	}

	mgr := system
	if mgr == "" || mgr == "auto" {
		mgr = detectInitSystem()
	}

	if install {
		installService(mgr, bin, configPath)
		return
	}
	uninstallService(mgr)
}

func installService(mgr, bin, conf string) {
	switch mgr {
	case "systemd":
		if err := os.WriteFile(systemdUnitPath, []byte(systemdUnit(bin, conf)), 0o644); err != nil {
			fatalf("write %s: %v", systemdUnitPath, err)
		}
		runOrDie("systemctl", "daemon-reload")
		runOrDie("systemctl", "enable", "--now", "meshd")
		fmt.Printf("installed systemd service (%s)\n  status: systemctl status meshd\n  logs:   journalctl -u meshd\n", systemdUnitPath)
	case "sysvinit":
		if err := os.WriteFile(sysvScriptPath, []byte(sysvScript(bin, conf)), 0o755); err != nil {
			fatalf("write %s: %v", sysvScriptPath, err)
		}
		if err := enableSysVBoot(); err != nil {
			fmt.Printf("note: %v\n", err)
		}
		runOrDie(sysvScriptPath, "start")
		fmt.Printf("installed sysvinit service (%s)\n  status: %s status\n", sysvScriptPath, sysvScriptPath)
	default:
		fatalf("unknown init system %q", mgr)
	}
}

func uninstallService(mgr string) {
	switch mgr {
	case "systemd":
		_ = exec.Command("systemctl", "disable", "--now", "meshd").Run()
		if err := os.Remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
			fatalf("remove %s: %v", systemdUnitPath, err)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		fmt.Println("removed systemd service")
	case "sysvinit":
		_ = exec.Command(sysvScriptPath, "stop").Run()
		_ = exec.Command("update-rc.d", "-f", "meshd", "remove").Run()
		_ = exec.Command("chkconfig", "meshd", "off").Run()
		if err := os.Remove(sysvScriptPath); err != nil && !os.IsNotExist(err) {
			fatalf("remove %s: %v", sysvScriptPath, err)
		}
		fmt.Println("removed sysvinit service")
	default:
		fatalf("unknown init system %q", mgr)
	}
}

// enableSysVBoot registers the init script for boot across distro flavors.
func enableSysVBoot() error {
	if err := exec.Command("update-rc.d", "meshd", "defaults").Run(); err == nil {
		return nil
	}
	if err := exec.Command("chkconfig", "meshd", "on").Run(); err == nil {
		return nil
	}
	return fmt.Errorf("neither update-rc.d nor chkconfig succeeded; enable boot start manually")
}

func runOrDie(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}
