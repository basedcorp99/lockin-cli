package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

type installation struct {
	Owner int `json:"owner"`
}
type envelope struct {
	req   request
	reply chan response
}
type enforcer interface{ Apply([]Policy) error }
type service struct {
	state     State
	firewall  enforcer
	persist   func(State) error
	health    string
	lastApply time.Time
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".lockin-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON document")
	}
	return nil
}
func cloneState(s State) State {
	// Policies and configuration are immutable snapshots; only lifecycle fields mutate.
	s.Sessions = slices.Clone(s.Sessions)
	s.Occurrences = maps.Clone(s.Occurrences)
	return s
}

func (s *service) commit(next State) error {
	if err := s.persist(next); err != nil {
		return fmt.Errorf("persist session state: %w", err)
	}
	s.state = next
	return nil
}
func (s *service) reconcile(now time.Time, force bool) error {
	next := cloneState(s.state)
	changed := Advance(&next, now)
	if changed {
		if err := s.commit(next); err != nil {
			s.health = err.Error()
			return err
		}
	}
	if !force && !changed && now.Sub(s.lastApply) < 30*time.Second && s.health == "" {
		return nil
	}
	err := s.firewall.Apply(ActivePolicies(s.state, now))
	s.lastApply = now
	if err != nil {
		s.health = err.Error()
		return err
	}
	s.health = ""
	return nil
}
func (s *service) handle(req request, now time.Time) response {
	err := s.reconcile(now, false)
	if err == nil && req.Command != "status" {
		next := cloneState(s.state)
		switch req.Command {
		case "start":
			err = StartManual(&next, now, time.Duration(req.Duration))
		case "break":
			err = TakeBreak(&next, now)
		case "reload":
			if req.Config == nil {
				err = errors.New("reload requires configuration")
			} else if err = ValidateConfig(*req.Config); err == nil {
				next.Config = *req.Config
				Advance(&next, now)
			}
		default:
			err = fmt.Errorf("unknown daemon command %q", req.Command)
		}
		if err == nil {
			err = s.commit(next)
			if err == nil {
				err = s.reconcile(now, true)
			}
		}
	}
	r := response{State: s.state, Now: now, EnforcementError: s.health}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

func runDaemon() error {
	if os.Geteuid() != 0 {
		return errors.New("daemon must run as root through launchd")
	}
	metaBytes, err := os.ReadFile(filepath.Join(stateDir, "installation.json"))
	if err != nil {
		return err
	}
	var meta installation
	if err = decodeStrict(metaBytes, &meta); err != nil {
		return err
	}
	if meta.Owner <= 0 {
		return errors.New("invalid daemon owner")
	}
	lock, err := os.OpenFile(filepath.Join(stateDir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another daemon is running")
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil {
		return err
	}
	var state State
	if err = decodeStrict(data, &state); err != nil {
		return fmt.Errorf("refusing corrupt state (existing firewall left intact): %w", err)
	}
	if err = ValidateConfig(state.Config); err != nil {
		return err
	}
	for _, session := range state.Sessions {
		if session.Kind != "manual" && session.Kind != "schedule" {
			return errors.New("invalid persisted session kind")
		}
		if !session.End.After(session.Start) {
			return errors.New("invalid persisted session interval")
		}
		if err = ValidateConfig(Config{Mode: session.Policy.Mode, Hosts: session.Policy.Hosts}); err != nil {
			return fmt.Errorf("invalid persisted policy: %w", err)
		}
	}
	fw, err := NewFirewall(stateDir)
	if err != nil {
		return err
	}
	svc := service{state: state, firewall: fw, persist: func(s State) error { return saveJSON(filepath.Join(stateDir, "state.json"), s) }}
	// A transient firewall failure must not prevent the control socket from exposing it.
	if err = svc.reconcile(time.Now(), true); err != nil {
		log.Printf("initial enforcement: %v", err)
	}
	if err = os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	// launchd's private umask also affects MkdirAll. The owner must be able to
	// traverse this root-owned directory; access is restricted by the socket.
	if err = os.Chmod(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	if err = os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	if err = os.Chown(socketPath, meta.Owner, -1); err != nil {
		return err
	}
	queue := make(chan envelope)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go serveConnection(conn, queue, done)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	log.Print("lockin daemon ready")
	for {
		select {
		case <-signals:
			return nil // Never clear restrictions on exit; launchd restarts us.
		case <-ticker.C:
			if e := svc.reconcile(time.Now(), false); e != nil {
				log.Printf("enforcement: %v", e)
			}
		case msg := <-queue:
			msg.reply <- svc.handle(msg.req, time.Now())
		}
	}
}
func serveConnection(conn net.Conn, queue chan<- envelope, done <-chan struct{}) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	dec := json.NewDecoder(io.LimitReader(conn, 1<<20))
	dec.DisallowUnknownFields()
	var req request
	if err := dec.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: err.Error()})
		return
	}
	msg := envelope{req: req, reply: make(chan response, 1)}
	select {
	case queue <- msg:
	case <-done:
		return
	case <-time.After(5 * time.Second):
		return
	}
	select {
	case r := <-msg.reply:
		_ = json.NewEncoder(conn).Encode(r)
	case <-done:
		return
	}
}
