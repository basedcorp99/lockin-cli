package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type observedEnforcement struct {
	policies []Policy
	fail     bool
}

func (f *observedEnforcement) Apply(p []Policy) error {
	if f.fail {
		return errors.New("firewall unavailable")
	}
	f.policies = p
	return nil
}

func TestFailedBreakPersistenceCannotUnlock(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	state := State{Config: Config{Mode: "blocklist", Hosts: []string{"example.com"}, Timezone: "UTC"}}
	if err := StartManual(&state, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	fw := &observedEnforcement{}
	svc := service{state: state, firewall: fw, persist: func(State) error { return errors.New("disk full") }}
	if err := svc.reconcile(now, true); err != nil {
		t.Fatal(err)
	}
	result := svc.handle(request{Command: "break"}, now.Add(time.Second))
	if result.Error == "" {
		t.Fatal("break succeeded without durable state")
	}
	if len(fw.policies) != 1 || svc.state.Sessions[0].BreakUsed {
		t.Fatal("failed transaction unlocked or consumed the break")
	}
	svc.persist = func(s State) error { return saveJSON(filepath.Join(t.TempDir(), "state.json"), s) }
	result = svc.handle(request{Command: "break"}, now.Add(2*time.Second))
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if len(fw.policies) != 0 {
		t.Fatal("committed emergency break did not unlock")
	}
}

func TestFailedEnforcementRetainsSessionAcrossRecovery(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	state := State{Config: Config{Mode: "blocklist", Hosts: []string{"example.com"}, Timezone: "UTC"}}
	fw := &observedEnforcement{}
	var durable State
	svc := service{state: state, firewall: fw, persist: func(s State) error { durable = cloneState(s); return nil }}
	if err := svc.reconcile(now, true); err != nil {
		t.Fatal(err)
	}
	fw.fail = true
	result := svc.handle(request{Command: "start", Duration: int64(time.Hour)}, now.Add(time.Second))
	if result.Error == "" {
		t.Fatal("firewall failure falsely reported success")
	}
	if len(durable.Sessions) != 1 {
		t.Fatal("committed session was discarded after firewall failure")
	}
	recovered := service{state: durable, firewall: &observedEnforcement{}, persist: func(State) error { return nil }}
	result = recovered.handle(request{Command: "start", Duration: int64(time.Minute)}, now.Add(2*time.Second))
	if result.Error == "" {
		t.Fatal("restart allowed replacing an active session with a shorter one")
	}
	if got := recovered.state.Sessions[0].End; !got.Equal(now.Add(time.Second + time.Hour)) {
		t.Fatalf("session deadline changed: %v", got)
	}
}
