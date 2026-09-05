package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The bundle is installed separately from the privileged executable. Its process
// runs only in the owner's GUI launchd domain and never receives root privileges.
func installNotificationBundle(source string, owner int) error {
	if source == "" {
		if _, err := os.Stat(notificationExecutable); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
	} else {
		source, err := filepath.Abs(source)
		if err != nil {
			return err
		}
		identity, err := command("/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(source, "Contents", "Info.plist"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(identity)) != notificationBundleID {
			return errors.New("notification bundle identity mismatch")
		}
		if _, err = command("/usr/bin/codesign", "--verify", "--strict", source); err != nil {
			return err
		}
		parent := filepath.Dir(notificationBundle)
		if err = os.MkdirAll(parent, 0755); err != nil {
			return err
		}
		if err = os.Chmod(parent, 0755); err != nil {
			return err
		}
		stage, err := os.MkdirTemp(parent, ".Lockin-*.app")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		if err = copyNotificationBundle(source, stage); err != nil {
			return err
		}
		if _, err = command("/usr/bin/codesign", "--verify", "--strict", stage); err != nil {
			return err
		}
		target := "gui/" + strconv.Itoa(owner) + "/" + notificationBundleID
		if _, running := command("/bin/launchctl", "print", target); running == nil {
			if _, err = command("/bin/launchctl", "bootout", target); err != nil {
				return err
			}
		}
		previous := notificationBundle + ".previous"
		if err = os.RemoveAll(previous); err != nil {
			return err
		}
		hadPrevious := false
		if _, err = os.Stat(notificationBundle); err == nil {
			if err = os.Rename(notificationBundle, previous); err != nil {
				return err
			}
			hadPrevious = true
		} else if !os.IsNotExist(err) {
			return err
		}
		if err = os.Rename(stage, notificationBundle); err != nil {
			if hadPrevious {
				err = errors.Join(err, os.Rename(previous, notificationBundle))
			}
			return err
		}
		if err = os.RemoveAll(previous); err != nil {
			return err
		}
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.lockin.notifications</string>
<key>ProgramArguments</key><array>
<string>/Library/Application Support/lockin/Lockin Alerts.app/Contents/MacOS/lockin-notify</string>
<string>--owner</string><string>%d</string>
</array>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>10</integer>
<key>Umask</key><integer>63</integer>
</dict></plist>
`, owner)
	if err := atomicWrite(notificationLaunchPath, []byte(plist), 0644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(owner)
	if _, err := command("/bin/launchctl", "print", domain); err != nil {
		fmt.Println("Notification helper installed; it will start at the owner's next graphical login.")
		return nil
	}
	if _, err := command("/bin/launchctl", "print", domain+"/"+notificationBundleID); err == nil {
		return nil
	}
	if _, err := command("/bin/launchctl", "bootstrap", domain, notificationLaunchPath); err != nil {
		return fmt.Errorf("notification helper installed but launch failed: %w", err)
	}
	fmt.Println("Installed background notification helper. Permission is requested only by: lockin alerts authorize")
	return nil
}

func copyNotificationBundle(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			if err = os.MkdirAll(target, 0755); err != nil {
				return err
			}
			return os.Chmod(target, 0755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported notification bundle entry %q (only regular files/directories are allowed)", relative)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		mode := os.FileMode(0644)
		if info.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		if err = output.Chmod(mode); err != nil {
			output.Close()
			return err
		}
		if _, err = io.Copy(output, input); err != nil {
			output.Close()
			return err
		}
		if err = output.Sync(); err != nil {
			output.Close()
			return err
		}
		return output.Close()
	})
}
