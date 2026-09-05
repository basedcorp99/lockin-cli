package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func command(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v: %w: %s", path, args, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func install(args []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	config := flags.String("config", "", "configuration file (required)")
	owner := flags.Int("owner", 0, "UID allowed to control sessions (required)")
	notifications := flags.String("notifications-bundle", "", "built Lockin Alerts.app bundle (use ./build.sh)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("installation requires sudo")
	}
	if *owner <= 0 || *config == "" {
		return errors.New("--owner UID and --config PATH are required")
	}
	data, err := os.ReadFile(*config)
	if err != nil {
		return err
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return err
	}
	if cfg.Alerts != nil && cfg.Alerts.Enabled && *notifications == "" {
		if _, err := os.Stat(notificationExecutable); err != nil {
			return errors.New("alerts are enabled but the notification helper is missing; install with ./install.sh")
		}
	}
	existing, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var retained State
		if err = decodeStrict(existing, &retained); err != nil {
			return fmt.Errorf("refusing to replace invalid session state: %w", err)
		}
		if err = ValidateConfig(retained.Config); err != nil {
			return err
		}
		metaBytes, e := os.ReadFile(filepath.Join(stateDir, "installation.json"))
		if e != nil {
			return e
		}
		var meta installation
		if e = decodeStrict(metaBytes, &meta); e != nil {
			return e
		}
		if meta.Owner != *owner {
			return errors.New("cannot change the owner of an installed daemon")
		}
	}
	if err = os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	if err = os.Chown(stateDir, 0, 0); err != nil {
		return err
	}
	if err = os.Chmod(stateDir, 0700); err != nil {
		return err
	}
	if existing == nil {
		if err = saveJSON(filepath.Join(stateDir, "installation.json"), installation{Owner: *owner}); err != nil {
			return err
		}
		if err = saveJSON(filepath.Join(stateDir, "state.json"), State{Config: cfg}); err != nil {
			return err
		}
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		return err
	}
	if err = atomicWrite(binaryPath, executable, 0755); err != nil {
		return err
	}
	if err = os.Chown(binaryPath, 0, 0); err != nil {
		return err
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.lockin.daemon</string>
<key>ProgramArguments</key><array><string>/usr/local/bin/lockin</string><string>daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/var/db/lockin/daemon.log</string>
<key>StandardErrorPath</key><string>/var/db/lockin/daemon.log</string>
</dict></plist>
`
	if err = atomicWrite(launchPath, []byte(plist), 0644); err != nil {
		return err
	}
	if _, running := command("/bin/launchctl", "print", "system/"+label); running == nil {
		if _, err = command("/bin/launchctl", "bootout", "system/"+label); err != nil {
			return err
		}
	}
	if _, err = command("/bin/launchctl", "bootstrap", "system", launchPath); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		r, e := call(request{Command: "status"})
		if e == nil && r.EnforcementError == "" {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("installed but daemon not healthy; inspect %s/daemon.log: %v %s", stateDir, e, r.EnforcementError)
		}
		time.Sleep(time.Second)
	}
	fmt.Println("Installed", binaryPath, "and", launchPath)
	if err = installNotificationBundle(*notifications, *owner); err != nil {
		return err
	}
	return nil
}
