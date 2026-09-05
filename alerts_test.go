package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAlertConnectionParserWithoutDescriptorFields(t *testing.T) {
	got, err := parseAlertConnections("p42\nPTCP\nn192.168.1.2:5000->203.0.113.4:443\nPUDP\nn192.168.1.2:5001->203.0.113.5:443\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].remote != netip.MustParseAddrPort("203.0.113.4:443") || got[1].remote != netip.MustParseAddrPort("203.0.113.5:443") {
		t.Fatalf("lost connections without f fields: %#v", got)
	}
}

func TestAlertConnectionParser(t *testing.T) {
	text := "p42\nf1\nPTCP\nn192.168.1.2:50000->203.0.113.4:443\nf2\nPUDP\nn[fe80::1%en0]:52000->[2001:db8::4%en0]:443\nf3\nPUDP\nn*:5353\nf4\nPTCP\nn*:80\nTST=LISTEN\nf5\nPTCP\nn192.168.1.2:50001->203.0.113.5:443\nTST=SYN_SENT\nf6\nPTCP\nn[::ffff:192.168.1.2]:50002->[::ffff:203.0.113.6]:443\nTST=ESTABLISHED\n"
	got, err := parseAlertConnections(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []alertConnection{
		{protocol: "TCP", local: netip.MustParseAddrPort("192.168.1.2:50000"), remote: netip.MustParseAddrPort("203.0.113.4:443")},
		{protocol: "UDP", local: netip.MustParseAddrPort("[fe80::1]:52000"), remote: netip.MustParseAddrPort("[2001:db8::4]:443")},
		{protocol: "TCP", local: netip.MustParseAddrPort("192.168.1.2:50002"), remote: netip.MustParseAddrPort("203.0.113.6:443")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed connections = %#v, want %#v", got, want)
	}
	for _, endpoint := range []string{"example.com:443", "203.0.113.4:https", "[2001:db8::4]:65536", "203.0.113.4:0"} {
		_, err := parseAlertConnections("p1\nf1\nPUDP\nn192.168.1.2:5000->" + endpoint + "\n")
		if err == nil {
			t.Errorf("accepted nonnumeric/invalid endpoint %q", endpoint)
		}
	}
}

func TestAlertConnectionMatching(t *testing.T) {
	targets := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("192.168.0.0/16")}
	for _, test := range []struct {
		name, protocol, local, remote string
		block, allow                  bool
	}{
		{"blocked IPv4", "TCP", "192.168.1.2:5000", "203.0.113.8:443", true, false},
		{"outside IPv6", "UDP", "[2001:db8::1]:5000", "[2001:db8:2::8]:443", false, true},
		{"allowed IPv6", "TCP", "[2001:db8::1]:5000", "[2001:db8:1::8]:443", true, false},
		{"private infrastructure", "TCP", "192.168.1.2:5000", "192.168.2.8:443", true, false},
		{"loopback", "TCP", "127.0.0.1:5000", "127.0.0.1:443", false, false},
		{"scoped infrastructure", "UDP", "[fe80::1]:5000", "[fe80::2]:443", false, false},
		{"multicast", "UDP", "192.168.1.2:5000", "224.0.0.251:5353", false, false},
		{"DNS exception", "TCP", "192.168.1.2:5000", "8.8.8.8:53", false, false},
		{"DHCP exception", "UDP", "192.168.1.2:68", "8.8.8.8:67", false, false},
		{"not DHCP", "UDP", "192.168.1.2:5000", "8.8.8.8:67", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := alertConnection{protocol: test.protocol, local: netip.MustParseAddrPort(test.local), remote: netip.MustParseAddrPort(test.remote)}
			if got := alertConnectionMatches(connection, Policy{Mode: "blocklist"}, targets); got != test.block {
				t.Errorf("blocklist match = %v, want %v", got, test.block)
			}
			if got := alertConnectionMatches(connection, Policy{Mode: "allowlist"}, targets); got != test.allow {
				t.Errorf("allowlist match = %v, want %v", got, test.allow)
			}
		})
	}
}

func TestAlertAllowlistResolutionDoesNotUsePartialResults(t *testing.T) {
	policy := Policy{Mode: "allowlist", Hosts: []string{"example.com", "other.example"}}
	lookup := func(_ context.Context, name string) ([]netip.Prefix, error) {
		if name == "other.example" {
			return nil, errors.New("resolver timeout")
		}
		if strings.HasPrefix(name, "www.") {
			return nil, firewallDNSMissing
		}
		return []netip.Prefix{netip.MustParsePrefix("203.0.113.8/32")}, nil
	}
	if targets, err := resolveAlertTargets(context.Background(), policy, lookup); err == nil || targets != nil {
		t.Fatalf("partial allowlist escaped suppression: %v, %v", targets, err)
	}
	policy.Hosts = policy.Hosts[:1]
	targets, err := resolveAlertTargets(context.Background(), policy, lookup)
	if err != nil || !reflect.DeepEqual(targets, []netip.Prefix{netip.MustParsePrefix("203.0.113.8/32")}) {
		t.Fatalf("missing optional www alias invalidated base domain: %v, %v", targets, err)
	}
}

func alertTestManager(t *testing.T) (*AlertManager, State, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	state := State{Config: Config{Mode: "blocklist", Hosts: []string{"203.0.113.8"}, Alerts: &AlertConfig{Enabled: true, Interval: "1m", SessionDuration: "30m"}}}
	manager := NewAlertManager(501)
	manager.Configure(state.Config, now)
	return manager, state, now
}

// Wait for the worker's bounded result channel, not wall-clock sleeps. Putting
// it back lets the public Tick/Poll path perform the actual state transition.
func awaitAlertSample(t *testing.T, manager *AlertManager) {
	t.Helper()
	select {
	case result := <-manager.results:
		manager.results <- result
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot worker did not complete")
	}
}

func offerFromTestSample(t *testing.T, manager *AlertManager, state State, now time.Time) *AlertOffer {
	t.Helper()
	manager.Tick(state, now)
	awaitAlertSample(t, manager)
	offer := manager.Poll(state, now.Add(time.Second), "authorized", "", "")
	if offer == nil {
		t.Fatal("matching unlocked snapshot did not offer a session")
	}
	return offer
}

func TestAlertCadenceAcknowledgmentAndExpiry(t *testing.T) {
	manager, state, now := alertTestManager(t)
	started := make(chan struct{}, 4)
	manager.sample = func(context.Context, int, Policy) (bool, error) {
		started <- struct{}{}
		return true, nil
	}
	manager.Tick(state, now.Add(59*time.Second))
	select {
	case <-started:
		t.Fatal("sample ran before configured interval")
	default:
	}
	offer := offerFromTestSample(t, manager, state, now.Add(time.Minute))
	if duration, err := manager.Start(state, now.Add(62*time.Second), offer.ID); err != nil || duration != 30*time.Minute {
		t.Fatalf("action duration = %v, %v", duration, err)
	}
	if repeated := manager.Poll(state, now.Add(63*time.Second), "authorized", offer.ID, ""); repeated != nil || !manager.Status().Pending {
		t.Fatal("acknowledged offer repeated or was cleared before its action expired")
	}
	if repeated := manager.Poll(state, now.Add(64*time.Second), "authorized", "", ""); repeated != nil {
		t.Fatal("acknowledgment was forgotten on the next poll")
	}
	if _, err := manager.Start(state, now.Add(2*time.Minute), offer.ID); err == nil || manager.Status().Pending {
		t.Fatal("offer remained actionable at expiry")
	}
}

func TestAlertFailedDeliveryDoesNotRepeatOrBecomeActionable(t *testing.T) {
	manager, state, now := alertTestManager(t)
	manager.sample = func(context.Context, int, Policy) (bool, error) { return true, nil }
	offer := offerFromTestSample(t, manager, state, now.Add(time.Minute))
	if manager.Poll(state, now.Add(62*time.Second), "authorized", offer.ID, "native error") != nil || manager.Status().Pending || manager.Status().DeliveryError == "" {
		t.Fatal("failed delivery was silently accepted or repeated")
	}
	if _, err := manager.Start(state, now.Add(63*time.Second), offer.ID); err == nil {
		t.Fatal("failed delivery remained actionable")
	}
}

func TestAlertActionsInvalidatedBySessionReloadConsumeAndRestart(t *testing.T) {
	for _, transition := range []string{"manual", "schedule", "break", "reload", "consume", "restart"} {
		t.Run(transition, func(t *testing.T) {
			manager, state, now := alertTestManager(t)
			manager.sample = func(context.Context, int, Policy) (bool, error) { return true, nil }
			offer := offerFromTestSample(t, manager, state, now.Add(time.Minute))
			actionTime := now.Add(62 * time.Second)
			switch transition {
			case "reload":
				manager.Configure(state.Config, actionTime)
			case "consume":
				manager.Consume(offer.ID)
			case "restart":
				manager = NewAlertManager(501)
				manager.Configure(state.Config, actionTime)
			default:
				kind := transition
				if kind == "break" {
					kind = "manual"
				}
				state.Sessions = []Session{{Kind: kind, End: now.Add(time.Hour), BreakUntil: now.Add(5 * time.Minute)}}
			}
			if _, err := manager.Start(state, actionTime, offer.ID); err == nil || manager.Status().Pending {
				t.Fatal("old offer survived transition")
			}
		})
	}
}

func TestAlertAsyncSampleDiscardedWhenSessionStartsOrConfigReloads(t *testing.T) {
	for _, reload := range []bool{false, true} {
		manager, state, now := alertTestManager(t)
		started := make(chan struct{})
		cancelled := make(chan struct{})
		manager.sample = func(ctx context.Context, _ int, _ Policy) (bool, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return true, nil
		}
		manager.Tick(state, now.Add(time.Minute))
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("worker did not start")
		}
		// An overdue tick must not start a second concurrent collector.
		manager.Tick(state, now.Add(2*time.Minute))
		if reload {
			manager.Configure(state.Config, now.Add(2*time.Minute))
		} else {
			state.Sessions = []Session{{Kind: "manual", End: now.Add(time.Hour), BreakUntil: now.Add(5 * time.Minute)}}
			manager.Tick(state, now.Add(2*time.Minute))
		}
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("obsolete collector was not cancelled")
		}
		awaitAlertSample(t, manager)
		if offer := manager.Poll(state, now.Add(121*time.Second), "authorized", "", ""); offer != nil || manager.Status().Pending || manager.Status().LastMatch != nil {
			t.Fatal("obsolete async match became a reminder")
		}
	}
}

func TestAlertNoMatchAndPermissionDoNotDeliver(t *testing.T) {
	manager, state, now := alertTestManager(t)
	manager.sample = func(context.Context, int, Policy) (bool, error) { return false, nil }
	manager.Tick(state, now.Add(time.Minute))
	awaitAlertSample(t, manager)
	if offer := manager.Poll(state, now.Add(61*time.Second), "authorized", "", ""); offer != nil || manager.Status().LastMatch == nil || *manager.Status().LastMatch {
		t.Fatal("empty sample produced a reminder or lost its successful status")
	}
	manager.sample = func(context.Context, int, Policy) (bool, error) { return true, nil }
	manager.Tick(state, now.Add(2*time.Minute))
	awaitAlertSample(t, manager)
	if offer := manager.Poll(state, now.Add(121*time.Second), "not_determined", "", ""); offer != nil {
		t.Fatal("offered delivery without notification permission")
	}
	if offer := manager.Poll(state, now.Add(122*time.Second), "authorized", "", ""); offer == nil {
		t.Fatal("explicitly authorized helper could not receive a still-valid offer")
	}
}

func TestAlertConfigValidationAndOmissionCompatibility(t *testing.T) {
	for _, alertJSON := range []string{
		`{"enabled":true,"interval":"59s"}`,
		`{"enabled":false,"interval":"25h"}`,
		`{"enabled":true,"session_duration":"0s"}`,
		`{"enabled":true,"message":"   "}`,
		`{"enabled":true,"message":"line\nline"}`,
		`{"enabled":true,"unexpected":true}`,
	} {
		if _, err := ParseConfig([]byte(`{"mode":"allowlist","hosts":[],"alerts":` + alertJSON + `}`)); err == nil {
			t.Errorf("accepted invalid alerts %s", alertJSON)
		}
	}
	cfg, err := ParseConfig([]byte(`{"mode":"allowlist","hosts":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encoded), `"alerts"`) {
		t.Fatalf("old config gained an alerts field: %s, %v", encoded, err)
	}
	cfg, err = ParseConfig([]byte(`{"mode":"allowlist","hosts":[],"alerts":{"enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveAlertConfig(cfg.Alerts)
	if err != nil || !resolved.enabled || resolved.interval != 10*time.Minute || resolved.duration != time.Hour {
		t.Fatalf("omitted alert settings did not resolve: %+v, %v", resolved, err)
	}
	encoded, err = json.Marshal(cfg.Alerts)
	if err != nil || string(encoded) != `{"enabled":true}` {
		t.Fatalf("resolving defaults changed persisted configuration: %s, %v", encoded, err)
	}
}
