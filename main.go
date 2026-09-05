package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateDir = "/var/db/lockin"
const socketPath = "/var/run/lockin/control.sock"
const binaryPath = "/usr/local/bin/lockin"
const launchPath = "/Library/LaunchDaemons/local.lockin.daemon.plist"
const label = "local.lockin.daemon"

const help = `lockin — CLI-only macOS focus sessions

  lockin start 90m           Start a manual session (also 30s, 1h30m, 2h)
  lockin break               Use the session's only emergency break, up to 3m
  lockin status [--json]     Show active sessions and enforcement health
  lockin reload [--config PATH]
                            Validate and accept configuration without restarting
  lockin check [--config PATH]
                            Validate configuration without changing anything
  lockin init [--config PATH]
                            Write an example configuration; never overwrite
  sudo lockin install --owner UID --config PATH
                            Install root launchd daemon and CLI

Default configuration: ~/.config/lockin/config.json
Duration: positive, at least one second; explicit units required.
There is deliberately no stop, shorten, or reset command.
Scheduled sessions cannot take a break. A schedule interrupts a manual break.
Reload affects future sessions only; active policy/end/break usage are retained.
Sessions survive daemon restarts and reboot. Schedules catch up after sleep.
The session timer continues during a break and while the machine is asleep.
Config uses mode (blocklist/allowlist), hosts, timezone, and optional schedules.
Recurring schedules: id, days [mon..sun], start/end HH:MM[:SS]. Days refer to
start day; end <= start means overnight. One-time schedules: id, from/until
RFC3339 timestamps. Omit enabled or use true to enable a schedule.
Hosts are DNS names (also www), IP addresses, or CIDRs, not URLs/wildcards.
Allowlist hosts are ALLOWED; blocklist hosts are BLOCKED. Shared IPs may affect
other domains. DNS/DHCP and loopback remain available. This is not protection
against an administrator, a VPN/proxy bypass, or changing the system clock.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lockin:", err)
		os.Exit(1)
	}
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(home, ".config", "lockin", "config.json")
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(help)
		return nil
	}
	switch args[0] {
	case "daemon":
		if len(args) != 1 {
			return errors.New("daemon accepts no arguments")
		}
		return runDaemon()
	case "install":
		return install(args[1:])
	case "init", "check", "reload":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := flags.String("config", configPath(), "configuration path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if args[0] == "init" {
			if err := os.MkdirAll(filepath.Dir(*path), 0700); err != nil {
				return err
			}
			f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = f.WriteString("{\n  \"mode\": \"blocklist\",\n  \"hosts\": [\"example.com\"],\n  \"timezone\": \"Local\",\n  \"schedules\": []\n}\n")
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			fmt.Println(*path)
			return nil
		}
		data, err := os.ReadFile(*path)
		if err != nil {
			return err
		}
		cfg, err := ParseConfig(data)
		if err != nil {
			return err
		}
		if args[0] == "check" {
			fmt.Println("Configuration valid:", *path)
			return nil
		}
		return callAndPrint(request{Command: "reload", Config: &cfg}, false)
	case "start":
		if len(args) != 2 {
			return errors.New("usage: lockin start 1h30m")
		}
		d, err := ParseDuration(args[1])
		if err != nil {
			return err
		}
		return callAndPrint(request{Command: "start", Duration: int64(d)}, false)
	case "break":
		if len(args) != 1 {
			return errors.New("usage: lockin break")
		}
		return callAndPrint(request{Command: "break"}, false)
	case "status":
		if len(args) > 2 || (len(args) == 2 && args[1] != "--json") {
			return errors.New("usage: lockin status [--json]")
		}
		return callAndPrint(request{Command: "status"}, len(args) == 2)
	default:
		return fmt.Errorf("unknown command %q; use lockin help", args[0])
	}
}

type request struct {
	Command  string  `json:"command"`
	Duration int64   `json:"duration,omitempty"`
	Config   *Config `json:"config,omitempty"`
}
type response struct {
	Error            string    `json:"error,omitempty"`
	EnforcementError string    `json:"enforcement_error,omitempty"`
	State            State     `json:"state"`
	Now              time.Time `json:"now"`
}

func call(req request) (response, error) {
	var result response
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return result, fmt.Errorf("daemon unavailable (install it first): %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return result, err
	}
	if err = json.NewDecoder(conn).Decode(&result); err != nil {
		return result, err
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}
func callAndPrint(req request, asJSON bool) error {
	r, err := call(req)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if e := enc.Encode(r); e != nil {
			return e
		}
	} else {
		if r.Now.IsZero() {
			return err
		}
		if len(r.State.Sessions) == 0 {
			fmt.Println("No active session.")
		} else {
			for _, s := range r.State.Sessions {
				remaining := s.End.Sub(r.Now).Round(time.Second)
				status := "locked"
				if r.Now.Before(s.BreakUntil) {
					status = "break until " + s.BreakUntil.Local().Format(time.RFC3339)
				}
				allowance := "no break (scheduled)"
				if s.Kind == "manual" {
					allowance = "one 3m break available"
					if s.BreakUsed {
						allowance = "break already used"
					}
				}
				fmt.Printf("%s: %s; %s remaining; ends %s; %s\n", s.Kind, status, remaining, s.End.Local().Format(time.RFC3339), allowance)
			}
		}
		fmt.Printf("Configuration: %s; %d hosts; %d schedules; timezone %s\n", r.State.Config.Mode, len(r.State.Config.Hosts), len(r.State.Config.Schedules), r.State.Config.Timezone)
		if req.Command == "reload" && err == nil {
			fmt.Println("Configuration reloaded. Active sessions are unchanged.")
		}
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.EnforcementError) != "" {
		return fmt.Errorf("enforcement unhealthy: %s", r.EnforcementError)
	}
	return nil
}
