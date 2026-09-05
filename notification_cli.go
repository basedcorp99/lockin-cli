package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const notificationBundle = "/Library/Application Support/lockin/Lockin Alerts.app"
const notificationExecutable = notificationBundle + "/Contents/MacOS/lockin-notify"
const notificationBundleID = "local.lockin.notifications"
const notificationLaunchPath = "/Library/LaunchAgents/local.lockin.notifications.plist"
const launchServicesRegister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

func alertsCommand(args []string) error {
	if len(args) != 1 || (args[0] != "authorize" && args[0] != "status") {
		return errors.New("usage: lockin alerts status | authorize")
	}
	if os.Geteuid() == 0 {
		return errors.New("notification commands must run as your normal logged-in user, not sudo")
	}
	if _, err := os.Stat(notificationExecutable); err != nil {
		return fmt.Errorf("notification helper is not installed; run ./install.sh: %w", err)
	}
	if args[0] == "authorize" {
		if _, err := command(launchServicesRegister, "-f", notificationBundle); err != nil {
			return err
		}
		if _, err := command("/usr/bin/open", "-g", "-b", notificationBundleID, "lockin-alerts://authorize"); err != nil {
			return err
		}
		fmt.Println("Requested notification authorization. Approve the macOS prompt; if previously denied, enable Lockin Alerts in System Settings → Notifications.")
		return nil
	}
	r, err := call(request{Command: "status"})
	if err != nil {
		return err
	}
	native, err := command(notificationExecutable, "--status")
	if err != nil {
		return fmt.Errorf("read notification permission: %w", err)
	}
	if !json.Valid(native) {
		return errors.New("notification helper returned invalid status JSON")
	}
	output := struct {
		Detector     *AlertStatus    `json:"detector"`
		Notification json.RawMessage `json:"notification"`
		Bundle       string          `json:"bundle"`
	}{r.Alerts, native, filepath.Clean(notificationBundle)}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
