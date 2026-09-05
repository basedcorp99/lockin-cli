package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const socketPath = "/var/run/lockin/control.sock"

type offer struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	Duration string `json:"duration"`
	Label    string `json:"label"`
}

type request struct {
	Command        string `json:"command"`
	Permission     string `json:"permission,omitempty"`
	AcknowledgedID string `json:"acknowledged_id,omitempty"`
	DeliveryError  string `json:"delivery_error,omitempty"`
	AlertID        string `json:"alert_id,omitempty"`
}

type response struct {
	Error            string `json:"error"`
	EnforcementError string `json:"enforcement_error"`
	Alert            *offer `json:"alert"`
	AlertsEnabled    bool   `json:"alerts_enabled"`
	AlertsClear      bool   `json:"alerts_clear"`
}

// Only the last attempted offer is retained: no browsing data or notification text.
// Recording before submission also prevents re-alerting after an interrupted send.
type deliveryRecord struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

var actionEvents = make(chan string, 16)
var helperDone = make(chan struct{})

func handoffAction(id string) {
	go func() {
		select {
		case actionEvents <- id:
		case <-helperDone:
		}
	}()
}

func exchange(ctx context.Context, req request) (response, error) {
	var out response
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return out, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return out, err
	}
	err = json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&out)
	return out, err
}

func saveRecord(path string, record deliveryRecord) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".delivery-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(record); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func loadRecord(path string) (deliveryRecord, error) {
	var record deliveryRecord
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	defer f.Close()
	err = json.NewDecoder(io.LimitReader(f, 16384)).Decode(&record)
	return record, err
}

func denied(err error, reply response) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || reply.Error == "permission denied"
}

func showResult(ctx context.Context, text string) {
	if err := nativeResult(ctx, text); err != nil {
		log.Printf("cannot display session result: %v", err)
	}
}

func startSession(ctx context.Context, id string) {
	reply, err := exchange(ctx, request{Command: "notification-start", AlertID: id})
	nativeClear()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Printf("session action transport failed: %v", err)
		showResult(ctx, "Could not confirm that the session started. Check lockin status before trying again.")
		return
	}
	if reply.Error != "" {
		log.Printf("session action rejected: %s", reply.Error)
		showResult(ctx, "Could not start the session: "+reply.Error)
		return
	}
	if reply.EnforcementError != "" {
		log.Printf("session enforcement failed: %s", reply.EnforcementError)
		showResult(ctx, "The session was saved, but enforcement needs attention: "+reply.EnforcementError)
	}
}

func coordinate(ctx context.Context, recordPath string, record deliveryRecord) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	poll := func() bool {
		permission, err := nativePermission(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("cannot read notification settings: %v", err)
			}
			permission = "unknown"
		}
		reply, err := exchange(ctx, request{
			Command: "notification-poll", Permission: permission,
			AcknowledgedID: record.ID, DeliveryError: record.Error,
		})
		if denied(err, reply) {
			return false
		}
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("notification poll failed: %v", err)
			}
			return true
		}
		if reply.AlertsClear || !reply.AlertsEnabled {
			nativeClear()
			return true
		}
		if reply.Error != "" {
			nativeClear()
			log.Printf("notification poll rejected: %s", reply.Error)
			return true
		}
		a := reply.Alert
		if a == nil || a.ID == "" || a.ID == record.ID || (permission != "authorized" && permission != "provisional") {
			return true
		}
		record = deliveryRecord{ID: a.ID, Error: "notification delivery did not complete"}
		if err := saveRecord(recordPath, record); err != nil {
			record.Error = "cannot persist notification delivery receipt"
			log.Printf("cannot persist notification receipt: %v", err)
			return true
		}
		err = nativeReminder(ctx, *a)
		record.Error = ""
		if err != nil {
			nativeClear()
			record.Error = err.Error()
			log.Printf("notification delivery failed: %v", err)
		}
		if err := saveRecord(recordPath, record); err != nil {
			log.Printf("cannot persist notification outcome: %v", err)
		}
		return true
	}
	if !poll() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-actionEvents:
			startSession(ctx, id)
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}

func run() int {
	mode := ""
	args := os.Args[1:]
	if len(args) == 2 && args[0] == "--owner" {
		owner, err := strconv.Atoi(args[1])
		if err != nil || owner < 0 {
			fmt.Fprintln(os.Stderr, "invalid installation owner")
			return 2
		}
		if os.Getuid() != owner {
			return 0
		}
	} else if len(args) > 0 {
		mode = args[0]
		if len(args) != 1 || (mode != "--status" && mode != "--authorize" && mode != "lockin-alerts://authorize") {
			fmt.Fprintln(os.Stderr, "usage: lockin-notify [--status | --authorize | --owner UID]")
			return 2
		}
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "lockin-notify must run as the logged-in installation owner, not root")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var record deliveryRecord
	var recordPath string
	if mode != "--status" {
		cache, err := os.UserCacheDir()
		if err != nil {
			log.Print(err)
			return 1
		}
		dir := filepath.Join(cache, "local.lockin.notifications")
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Print(err)
			return 1
		}
		lock, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Print(err)
			return 1
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) {
				if mode != "" {
					if err := exec.CommandContext(ctx, "/usr/bin/open", "-g", "-b", "local.lockin.notifications", "lockin-alerts://authorize").Run(); err != nil {
						log.Printf("cannot forward authorization request: %v", err)
						return 1
					}
				}
				return 0
			}
			log.Print(err)
			return 1
		}
		recordPath = filepath.Join(dir, "delivery.json")
		record, err = loadRecord(recordPath)
		if err != nil {
			log.Printf("cannot read notification receipt: %v", err)
			return 1
		}
	}
	if err := nativeInit(mode == "--authorize" || strings.HasPrefix(mode, "lockin-alerts://"), mode == "--status"); err != nil {
		log.Print(err)
		return 1
	}
	finished := make(chan int, 1)
	go func() {
		code := 0
		if mode == "--status" {
			permission, err := nativePermission(ctx)
			if err != nil {
				log.Print(err)
				code = 1
			} else if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"permission": permission}); err != nil {
				log.Print(err)
				code = 1
			}
		} else {
			coordinate(ctx, recordPath, record)
		}
		finished <- code
		nativeStop()
	}()
	nativeRun()
	cancel()
	code := <-finished
	close(helperDone)
	return code
}

func main() {
	os.Exit(run())
}
