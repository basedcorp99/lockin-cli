package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func instant(t *testing.T, value string) time.Time {
	t.Helper()
	result, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func location(t *testing.T, name string) *time.Location {
	t.Helper()
	result, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testConfig(schedules ...Schedule) Config {
	return Config{Mode: "blocklist", Hosts: []string{"twitter.com"}, Timezone: "Europe/Rome", Schedules: schedules}
}

func restartState(t *testing.T, state State) State {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var restored State
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	return restored
}

func TestConfigStrictnessAndHostNormalization(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"mode":"blocklist","hosts":["TWITTER.COM.","twitter.com","192.0.2.27/24","2001:0DB8::1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"twitter.com", "192.0.2.0/24", "2001:db8::1"}
	if !reflect.DeepEqual(cfg.Hosts, want) {
		t.Fatalf("hosts = %v, want %v", cfg.Hosts, want)
	}
	invalid := []string{
		`{"mode":"blocklist","hosts":["twitter.com"],"unknown":true}`,
		`{"mode":"blocklist","hosts":["twitter.com"]} {}`,
		`{"mode":"blocklist","hosts":["twitter.com"]} garbage`,
		`{"mode":"blocklist","hosts":[]}`,
		`{"hosts":["twitter.com"]}`,
		`{"mode":"blocklist","hosts":["https://twitter.com"]}`,
		`{"mode":"blocklist","hosts":["twitter.com:443"]}`,
		`{"mode":"blocklist","hosts":["*.twitter.com"]}`,
		`{"mode":"blocklist","hosts":["tést.com"]}`,
		`{"mode":"blocklist","hosts":["fe80::1%en0"]}`,
		`{"mode":"blocklist","hosts":["192.0.2.1/33"]}`,
		`{"mode":"allowlist","hosts":[],"timezone":"Not/AZone"}`,
		`{"mode":"allowlist","schedules":[{"id":"x","days":["mon"],"start":"9:00","end":"17:00"}]}`,
		`{"mode":"allowlist","schedules":[{"id":"x","days":["mon"],"start":"09:00","end":"17:00","from":"2026-09-07T09:00:00Z","until":"2026-09-07T17:00:00Z"}]}`,
		`{"mode":"allowlist","schedules":[{"id":"x","days":["mon"],"start":"09:00","end":"17:00","typo":true}]}`,
		`{"mode":"allowlist","schedules":[{"id":"x","days":["mon"],"start":"09:00","end":"17:00"},{"id":"x","days":["tue"],"start":"09:00","end":"17:00"}]}`,
	}
	for _, input := range invalid {
		if _, err := ParseConfig([]byte(input)); err == nil {
			t.Errorf("accepted invalid config: %s", input)
		}
	}
	if cfg, err := ParseConfig([]byte(`{"mode":"allowlist","hosts":[]}`)); err != nil || len(cfg.Hosts) != 0 {
		t.Fatalf("empty allowlist must be accepted: %+v, %v", cfg, err)
	}
}

func TestDurationContract(t *testing.T) {
	for value, want := range map[string]time.Duration{"1s": time.Second, "1h30m": 90 * time.Minute, "1.5s": 1500 * time.Millisecond} {
		got, err := ParseDuration(value)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "90", "0", "0s", "-1h", "999ms", "999999999999999999999h"} {
		if _, err := ParseDuration(value); err == nil {
			t.Errorf("accepted duration %q", value)
		}
	}
}

func TestDSTFoldsGapsAndNonHourChanges(t *testing.T) {
	cases := []struct {
		name, zone, date, start, end, wantStart, wantEnd string
	}{
		{"spring gap", "Europe/Rome", "2026-03-29", "02:30", "04:00", "2026-03-29T01:00:00Z", "2026-03-29T02:00:00Z"},
		{"autumn fold", "Europe/Rome", "2026-10-25", "02:15", "02:45", "2026-10-25T00:15:00Z", "2026-10-25T01:45:00Z"},
		{"half hour gap", "Australia/Lord_Howe", "2026-10-04", "02:15", "03:00", "2026-10-03T15:30:00Z", "2026-10-03T16:00:00Z"},
		{"skipped date", "Pacific/Apia", "2011-12-30", "09:00", "17:00", "2011-12-30T10:00:00Z", "2011-12-30T10:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			date := instant(t, tc.date+"T00:00:00Z")
			startClock, _ := parseClock(tc.start)
			endClock, _ := parseClock(tc.end)
			loc := location(t, tc.zone)
			if got := resolveWall(date, startClock, loc, false); !got.Equal(instant(t, tc.wantStart)) {
				t.Errorf("start = %s, want %s", got, tc.wantStart)
			}
			if got := resolveWall(date, endClock, loc, true); !got.Equal(instant(t, tc.wantEnd)) {
				t.Errorf("end = %s, want %s", got, tc.wantEnd)
			}
		})
	}
	// A reboot during the second 02:30 must recover the whole folded window.
	state := State{Config: testConfig(Schedule{ID: "fold", Days: []string{"sun"}, Start: "02:15", End: "02:45"})}
	Advance(&state, instant(t, "2026-10-25T01:30:00Z"))
	if len(ActivePolicies(state, instant(t, "2026-10-25T01:30:00Z"))) != 1 {
		t.Fatal("folded schedule was not recovered during repeated clock hour")
	}
	Advance(&state, instant(t, "2026-10-25T01:45:00Z"))
	if len(state.Sessions) != 0 {
		t.Fatal("schedule must end at the latest folded end, exclusively")
	}
}

func TestOvernightCalendarDaysAcrossDSTAndWeekBoundary(t *testing.T) {
	state := State{Config: testConfig(Schedule{ID: "night", Days: []string{"sat"}, Start: "23:00", End: "04:00"})}
	now := instant(t, "2026-03-29T01:30:00Z")
	Advance(&state, now)
	if len(state.Sessions) != 1 {
		t.Fatalf("overnight wake must recover one session: %+v", state.Sessions)
	}
	if !state.Sessions[0].End.Equal(instant(t, "2026-03-29T02:00:00Z")) {
		t.Fatalf("overnight end used elapsed-day arithmetic: %s", state.Sessions[0].End)
	}
	state = State{Config: testConfig(Schedule{ID: "week", Days: []string{"sun"}, Start: "23:00", End: "01:00"})}
	Advance(&state, instant(t, "2026-09-06T22:30:00Z"))
	if len(state.Sessions) != 1 || state.Sessions[0].ID != "schedule:week:2026-09-06" {
		t.Fatalf("Monday overnight must belong to Sunday: %+v", state.Sessions)
	}
}

func TestOverlappingOccurrencesAndEqualClocks(t *testing.T) {
	state := State{Config: testConfig(
		Schedule{ID: "day", Days: []string{"mon"}, Start: "09:00", End: "17:00"},
		Schedule{ID: "all-day", Days: []string{"mon"}, Start: "09:00", End: "09:00"},
	)}
	now := instant(t, "2026-09-07T08:00:00Z")
	Advance(&state, now)
	if len(ActivePolicies(state, now)) != 2 {
		t.Fatal("overlapping occurrences must remain independent")
	}
	Advance(&state, instant(t, "2026-09-07T15:00:00Z"))
	if len(state.Sessions) != 1 || state.Sessions[0].ID != "schedule:all-day:2026-09-07" {
		t.Fatalf("equal clocks must mean next calendar day, not zero duration: %+v", state.Sessions)
	}
	Advance(&state, instant(t, "2026-09-08T07:00:00Z"))
	if len(state.Sessions) != 0 {
		t.Fatal("all-day occurrence did not end")
	}
}

func TestReloadCannotReplaceOrResurrectOccurrence(t *testing.T) {
	state := State{Config: testConfig(Schedule{ID: "work", Days: []string{"mon"}, Start: "09:00", End: "17:00"})}
	now := instant(t, "2026-09-07T08:00:00Z")
	Advance(&state, now)
	original := state.Sessions[0]
	state.Config.Hosts[0] = "example.com"
	state.Config.Schedules[0].End = "12:00"
	Advance(&state, now.Add(time.Hour))
	if len(state.Sessions) != 1 || !reflect.DeepEqual(state.Sessions[0], original) {
		t.Fatal("reload modified an active snapshot")
	}
	state.Config.Schedules = nil
	Advance(&state, now.Add(2*time.Hour))
	if len(state.Sessions) != 1 {
		t.Fatal("removing schedule removed its active occurrence")
	}
	// Keep the same stable ID, but extend today's config after the original
	// snapshot ended. A restart must not allow that occurrence to reappear.
	state.Config.Schedules = []Schedule{{ID: "work", Days: []string{"mon"}, Start: "09:00", End: "20:00"}}
	state = restartState(t, state)
	Advance(&state, instant(t, "2026-09-07T16:00:00Z"))
	if len(state.Sessions) != 0 {
		t.Fatal("edited same-day occurrence was resurrected")
	}
	Advance(&state, instant(t, "2026-09-14T08:00:00Z"))
	if len(state.Sessions) != 1 || state.Sessions[0].Policy.Hosts[0] != "example.com" {
		t.Fatal("next week's distinct occurrence did not use new configuration")
	}
}

func TestOneTimeScheduleDisabledAndRestartDedup(t *testing.T) {
	disabled := false
	window := Schedule{ID: "once", From: "2026-09-07T09:00:00Z", Until: "2026-09-07T17:00:00Z", Enabled: &disabled}
	state := State{Config: testConfig(window)}
	now := instant(t, "2026-09-07T10:00:00Z")
	Advance(&state, now)
	if len(state.Sessions) != 0 {
		t.Fatal("disabled occurrence activated")
	}
	state.Config.Schedules[0].Enabled = nil
	Advance(&state, now)
	state = restartState(t, state)
	if Advance(&state, now) || len(state.Sessions) != 1 {
		t.Fatal("restart duplicated or changed the one-time occurrence")
	}
	state.Config.Schedules[0].Until = "2026-09-08T17:00:00Z"
	Advance(&state, instant(t, "2026-09-07T18:00:00Z"))
	if len(state.Sessions) != 0 {
		t.Fatal("one-time schedule extension resurrected the original occurrence")
	}
}

func TestManualBreakConsumptionSurvivesRestart(t *testing.T) {
	state := State{Config: testConfig()}
	now := instant(t, "2026-09-07T08:00:00Z")
	if err := StartManual(&state, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := TakeBreak(&state, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state = restartState(t, state)
	if got := ActivePolicies(state, now.Add(2*time.Minute)); len(got) != 0 {
		t.Fatal("break did not survive restart")
	}
	if err := StartManual(&state, now.Add(2*time.Minute), 2*time.Hour); err == nil {
		t.Fatal("active manual session could be replaced, resetting its break")
	}
	Advance(&state, now.Add(4*time.Minute))
	if len(ActivePolicies(state, now.Add(4*time.Minute))) != 1 {
		t.Fatal("manual restrictions did not resume at break end")
	}
	if err := TakeBreak(&state, now.Add(5*time.Minute)); err == nil {
		t.Fatal("second break was accepted")
	}
	Advance(&state, now.Add(time.Hour))
	if len(ActivePolicies(state, now.Add(time.Hour))) != 0 {
		t.Fatal("manual session did not expire")
	}
	if err := StartManual(&state, now.Add(time.Hour), 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := TakeBreak(&state, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !state.Sessions[0].BreakUntil.Equal(state.Sessions[0].End) {
		t.Fatal("short-session break must be capped at the manual end")
	}
}

func TestScheduleCancelsBreakWithoutRefund(t *testing.T) {
	state := State{Config: testConfig(Schedule{ID: "work", From: "2026-09-07T08:02:00Z", Until: "2026-09-07T08:03:00Z"})}
	now := instant(t, "2026-09-07T08:00:00Z")
	if err := StartManual(&state, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := TakeBreak(&state, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	Advance(&state, now.Add(2*time.Minute))
	if len(ActivePolicies(state, now.Add(2*time.Minute))) != 2 {
		t.Fatal("new schedule failed to restore both policies immediately")
	}
	if err := TakeBreak(&state, now.Add(2*time.Minute)); err == nil {
		t.Fatal("break bypassed active schedule")
	}
	Advance(&state, now.Add(3*time.Minute))
	if len(ActivePolicies(state, now.Add(3*time.Minute))) != 1 {
		t.Fatal("cancelled break resumed after schedule ended")
	}
	if err := TakeBreak(&state, now.Add(3*time.Minute)); err == nil {
		t.Fatal("cancelled break was refunded")
	}
}

func TestScheduleBlocksUnusedBreakAndClockRollback(t *testing.T) {
	state := State{Config: testConfig(Schedule{ID: "work", From: "2026-09-07T08:00:00Z", Until: "2026-09-07T08:02:00Z"})}
	now := instant(t, "2026-09-07T08:00:00Z")
	if err := StartManual(&state, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := TakeBreak(&state, now); err == nil {
		t.Fatal("unused break bypassed schedule")
	}
	if len(ActivePolicies(state, now.Add(-time.Hour))) != 2 {
		t.Fatal("backwards clock adjustment temporarily unlocked started sessions")
	}
	if err := TakeBreak(&state, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("rejected scheduled break must not consume manual allowance: %v", err)
	}
}
