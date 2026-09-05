package main

import (
	"fmt"
	"strings"
	"time"
)

type Session struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Policy     Policy    `json:"policy"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	BreakUsed  bool      `json:"break_used"`
	BreakUntil time.Time `json:"break_until"`
}

type State struct {
	Config   Config    `json:"config"`
	Sessions []Session `json:"sessions"`
	// Recurring occurrences expire after their civil date is no longer reachable
	// in any timezone. One-time occurrences have a zero expiry and stay recorded.
	// Keeping this separate from sessions prevents config edits resurrecting an
	// already completed occurrence or replacing its original policy snapshot.
	Occurrences map[string]time.Time `json:"occurrences,omitempty"`
}

// Advance catches active windows after sleep/restart, without replaying windows
// that ended while offline. Already-started sessions are immutable snapshots.
// The caller must persist changed state before applying its active policies.
func Advance(state *State, now time.Time) bool {
	changed := false
	for id, expiry := range state.Occurrences {
		if !expiry.IsZero() && !now.Before(expiry) {
			delete(state.Occurrences, id)
			changed = true
		}
	}
	kept := state.Sessions[:0]
	for _, session := range state.Sessions {
		if session.Kind == "schedule" {
			if state.Occurrences == nil {
				state.Occurrences = make(map[string]time.Time)
			}
			if _, exists := state.Occurrences[session.ID]; !exists {
				expiry := time.Time{}
				if !strings.HasSuffix(session.ID, ":once") {
					expiry = session.End.AddDate(0, 0, 4)
				}
				state.Occurrences[session.ID] = expiry
				changed = true
			}
		}
		if !now.Before(session.End) {
			changed = true
			continue
		}
		if !session.BreakUntil.IsZero() && !now.Before(session.BreakUntil) {
			session.BreakUntil = time.Time{}
			changed = true
		}
		kept = append(kept, session)
	}
	state.Sessions = kept

	loc, err := configLocation(state.Config)
	if err == nil {
		local := now.In(loc)
		// UTC is just a civil-date container here, not a 24-hour local-day step.
		today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
		for _, schedule := range state.Config.Schedules {
			if schedule.Enabled != nil && !*schedule.Enabled {
				continue
			}
			if schedule.From != "" || schedule.Until != "" {
				start, startErr := time.Parse(time.RFC3339, schedule.From)
				end, endErr := time.Parse(time.RFC3339, schedule.Until)
				if startErr == nil && endErr == nil && !now.Before(start) && now.Before(end) {
					if addOccurrence(state, "schedule:"+schedule.ID+":once", start, end, time.Time{}) {
						changed = true
					}
				}
				continue
			}
			startClock, startErr := parseClock(schedule.Start)
			endClock, endErr := parseClock(schedule.End)
			if startErr != nil || endErr != nil {
				continue
			}
			for daysAgo := 1; daysAgo >= 0; daysAgo-- {
				date := today.AddDate(0, 0, -daysAgo)
				if !scheduleHasDay(schedule, date.Weekday()) {
					continue
				}
				endDate := date
				if endClock <= startClock {
					endDate = date.AddDate(0, 0, 1)
				}
				start := resolveWall(date, startClock, loc, false)
				end := resolveWall(endDate, endClock, loc, true)
				if start.IsZero() || end.IsZero() || now.Before(start) || !now.Before(end) {
					continue
				}
				id := "schedule:" + schedule.ID + ":" + date.Format("2006-01-02")
				if addOccurrence(state, id, start, end, date.AddDate(0, 0, 4)) {
					changed = true
				}
			}
		}
	}

	if hasActiveSchedule(*state, now) {
		for i := range state.Sessions {
			if state.Sessions[i].Kind == "manual" && !state.Sessions[i].BreakUntil.IsZero() {
				state.Sessions[i].BreakUntil = time.Time{}
				changed = true
			}
		}
	}
	return changed
}

func addOccurrence(state *State, id string, start, end, expiry time.Time) bool {
	if _, exists := state.Occurrences[id]; exists {
		return false
	}
	if state.Occurrences == nil {
		state.Occurrences = make(map[string]time.Time)
	}
	state.Occurrences[id] = expiry
	state.Sessions = append(state.Sessions, Session{
		ID: id, Kind: "schedule", Policy: snapshotPolicy(state.Config), Start: start, End: end,
	})
	return true
}

func scheduleHasDay(schedule Schedule, weekday time.Weekday) bool {
	for _, day := range schedule.Days {
		if candidate, ok := weekdays[day]; ok && candidate == weekday {
			return true
		}
	}
	return false
}

// resolveWall enumerates the timezone's constant-offset intervals around the
// civil time, rather than accepting time.Date's unspecified DST choice. Folds
// use the earliest start/latest end; a gap advances to its first valid instant.
// ZoneBounds also handles non-hour transitions and whole skipped civil dates.
func resolveWall(date time.Time, clock int, loc *time.Location, latest bool) time.Time {
	wall := time.Date(date.Year(), date.Month(), date.Day(), clock/3600, clock/60%60, clock%60, 0, time.UTC)
	limit := wall.Add(72 * time.Hour)
	var result, next, nextWall time.Time
	for cursor := wall.Add(-72 * time.Hour); cursor.Before(limit); {
		local := cursor.In(loc)
		_, offset := local.Zone()
		start, end := local.ZoneBounds()
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		if civilTime(candidate.In(loc)).Equal(wall) {
			if result.IsZero() || (latest && candidate.After(result)) || (!latest && candidate.Before(result)) {
				result = candidate
			}
		}
		if !start.IsZero() {
			startWall := civilTime(start.In(loc))
			if startWall.After(wall) && (next.IsZero() || startWall.Before(nextWall)) {
				next, nextWall = start, startWall
			}
		}
		if end.IsZero() || !end.After(cursor) {
			break
		}
		cursor = end
	}
	if result.IsZero() {
		return next
	}
	return result
}

func civilTime(value time.Time) time.Time {
	return time.Date(value.Year(), value.Month(), value.Day(), value.Hour(), value.Minute(), value.Second(), value.Nanosecond(), time.UTC)
}

func snapshotPolicy(cfg Config) Policy {
	return Policy{Mode: cfg.Mode, Hosts: append([]string(nil), cfg.Hosts...)}
}

// Persisted sessions have already started; a backwards clock change must not
// temporarily disable them simply because now is earlier than their Start.
func hasActiveSchedule(state State, now time.Time) bool {
	for _, session := range state.Sessions {
		if session.Kind == "schedule" && now.Before(session.End) {
			return true
		}
	}
	return false
}

func StartManual(state *State, now time.Time, duration time.Duration) error {
	if duration < time.Second {
		return fmt.Errorf("duration must be at least 1s")
	}
	if err := ValidateConfig(state.Config); err != nil {
		return err
	}
	Advance(state, now)
	for _, session := range state.Sessions {
		if session.Kind == "manual" && now.Before(session.End) {
			return fmt.Errorf("a manual session is already active until %s; it cannot be replaced or extended", session.End.Format(time.RFC3339))
		}
	}
	end := now.Add(duration)
	if end.Year() > 9999 || end.Year() < 0 {
		return fmt.Errorf("session end cannot be represented in durable JSON state")
	}
	state.Sessions = append(state.Sessions, Session{
		ID:   fmt.Sprintf("manual:%d:%09d", now.Unix(), now.Nanosecond()),
		Kind: "manual", Policy: snapshotPolicy(state.Config), Start: now, End: end,
	})
	return nil
}

func TakeBreak(state *State, now time.Time) error {
	Advance(state, now)
	if hasActiveSchedule(*state, now) {
		return fmt.Errorf("emergency breaks are unavailable while a scheduled session is active")
	}
	for i := range state.Sessions {
		session := &state.Sessions[i]
		if session.Kind != "manual" || !now.Before(session.End) {
			continue
		}
		if session.BreakUsed {
			return fmt.Errorf("this manual session has already used its emergency break")
		}
		session.BreakUsed = true
		session.BreakUntil = now.Add(3 * time.Minute)
		if session.BreakUntil.After(session.End) {
			session.BreakUntil = session.End
		}
		return nil
	}
	return fmt.Errorf("no active manual session")
}

// ActivePolicies preserves separate snapshots so the firewall can combine them
// restrictively. A schedule overrides a break even before Advance clears it.
func ActivePolicies(state State, now time.Time) []Policy {
	var policies []Policy
	scheduled := hasActiveSchedule(state, now)
	for _, session := range state.Sessions {
		if !now.Before(session.End) {
			continue
		}
		if session.Kind == "manual" && !scheduled && now.Before(session.BreakUntil) {
			continue
		}
		policies = append(policies, session.Policy)
	}
	return policies
}
