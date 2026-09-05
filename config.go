package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Policy struct {
	Mode  string   `json:"mode"`
	Hosts []string `json:"hosts"`
}

type Config struct {
	Mode      string     `json:"mode"`
	Hosts     []string   `json:"hosts"`
	Timezone  string     `json:"timezone,omitempty"`
	Schedules []Schedule `json:"schedules,omitempty"`
}

// Days name the day a recurring window starts. End <= Start ends the next day.
// From and Until instead specify a single absolute window.
type Schedule struct {
	ID      string   `json:"id"`
	Enabled *bool    `json:"enabled,omitempty"`
	Days    []string `json:"days,omitempty"`
	Start   string   `json:"start,omitempty"`
	End     string   `json:"end,omitempty"`
	From    string   `json:"from,omitempty"`
	Until   string   `json:"until,omitempty"`
}

var scheduleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
	"sat": time.Saturday,
}

func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("config must contain exactly one JSON object")
		}
		return Config{}, fmt.Errorf("trailing config data: %w", err)
	}
	if err := ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	hosts := make([]string, 0, len(cfg.Hosts))
	seen := make(map[string]bool, len(cfg.Hosts))
	for _, host := range cfg.Hosts {
		normalized, _ := normalizeHost(host)
		if !seen[normalized] {
			hosts = append(hosts, normalized)
			seen[normalized] = true
		}
	}
	cfg.Hosts = hosts
	return cfg, nil
}

func ValidateConfig(cfg Config) error {
	if cfg.Mode != "blocklist" && cfg.Mode != "allowlist" {
		return fmt.Errorf("mode must be blocklist or allowlist")
	}
	if cfg.Mode == "blocklist" && len(cfg.Hosts) == 0 {
		return fmt.Errorf("blocklist requires at least one host")
	}
	for i, host := range cfg.Hosts {
		if _, err := normalizeHost(host); err != nil {
			return fmt.Errorf("hosts[%d]: %w", i, err)
		}
	}
	if _, err := configLocation(cfg); err != nil {
		return err
	}
	ids := make(map[string]bool, len(cfg.Schedules))
	for i, schedule := range cfg.Schedules {
		if err := validateSchedule(schedule); err != nil {
			return fmt.Errorf("schedules[%d]: %w", i, err)
		}
		if ids[schedule.ID] {
			return fmt.Errorf("duplicate schedule id %q", schedule.ID)
		}
		ids[schedule.ID] = true
	}
	return nil
}

var locationCache sync.Map

func configLocation(cfg Config) (*time.Location, error) {
	if cfg.Timezone == "" || cfg.Timezone == "Local" {
		return time.Local, nil
	}
	if cached, ok := locationCache.Load(cfg.Timezone); ok {
		return cached.(*time.Location), nil
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, fmt.Errorf("timezone %q: %w", cfg.Timezone, err)
	}
	cached, _ := locationCache.LoadOrStore(cfg.Timezone, loc)
	return cached.(*time.Location), nil
}

func validateSchedule(s Schedule) error {
	if !scheduleIDPattern.MatchString(s.ID) {
		return fmt.Errorf("id must be 1-64 ASCII letters, digits, underscores or hyphens, beginning with a letter or digit")
	}
	if s.From != "" || s.Until != "" {
		if len(s.Days) != 0 || s.Start != "" || s.End != "" {
			return fmt.Errorf("schedule %q: from/until cannot be combined with days/start/end", s.ID)
		}
		from, err := time.Parse(time.RFC3339, s.From)
		if err != nil {
			return fmt.Errorf("schedule %q: from must be RFC3339: %w", s.ID, err)
		}
		until, err := time.Parse(time.RFC3339, s.Until)
		if err != nil {
			return fmt.Errorf("schedule %q: until must be RFC3339: %w", s.ID, err)
		}
		if !until.After(from) {
			return fmt.Errorf("schedule %q: until must be after from", s.ID)
		}
		return nil
	}
	if len(s.Days) == 0 {
		return fmt.Errorf("schedule %q: days must contain at least one weekday", s.ID)
	}
	seen := make(map[string]bool, len(s.Days))
	for _, day := range s.Days {
		if _, ok := weekdays[day]; !ok {
			return fmt.Errorf("schedule %q: invalid day %q (use mon, tue, wed, thu, fri, sat, sun)", s.ID, day)
		}
		if seen[day] {
			return fmt.Errorf("schedule %q: duplicate day %q", s.ID, day)
		}
		seen[day] = true
	}
	if _, err := parseClock(s.Start); err != nil {
		return fmt.Errorf("schedule %q start: %w", s.ID, err)
	}
	if _, err := parseClock(s.End); err != nil {
		return fmt.Errorf("schedule %q end: %w", s.ID, err)
	}
	return nil
}

func parseClock(value string) (int, error) {
	if len(value) != 5 && len(value) != 8 {
		return 0, fmt.Errorf("%q must be HH:MM or HH:MM:SS", value)
	}
	for i := range value {
		if i == 2 || i == 5 {
			if value[i] != ':' {
				return 0, fmt.Errorf("%q must be HH:MM or HH:MM:SS", value)
			}
		} else if value[i] < '0' || value[i] > '9' {
			return 0, fmt.Errorf("%q must be HH:MM or HH:MM:SS", value)
		}
	}
	hour, _ := strconv.Atoi(value[:2])
	minute, _ := strconv.Atoi(value[3:5])
	second := 0
	if len(value) == 8 {
		second, _ = strconv.Atoi(value[6:8])
	}
	if hour > 23 || minute > 59 || second > 59 {
		return 0, fmt.Errorf("%q is not a valid clock time", value)
	}
	return hour*3600 + minute*60 + second, nil
}

func normalizeHost(host string) (string, error) {
	if host == "" || strings.TrimSpace(host) != host {
		return "", fmt.Errorf("host %q is empty or has surrounding whitespace", host)
	}
	if prefix, err := netip.ParsePrefix(host); err == nil {
		return prefix.Masked().String(), nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("host %q: scoped IP addresses are unsupported", host)
		}
		return addr.Unmap().String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 {
		return "", fmt.Errorf("host must be an ASCII DNS name, IP address or CIDR")
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label in %q", host)
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				allNumeric = false
			}
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", fmt.Errorf("host %q must be an ASCII DNS name, IP address or CIDR; URLs, ports and wildcards are unsupported", host)
			}
		}
	}
	if allNumeric {
		return "", fmt.Errorf("host %q is not a valid IP address", host)
	}
	return host, nil
}

// ParseDuration accepts Go duration syntax, including compounds and fractional
// units. Bare numbers, durations below one second, and overflow are rejected.
func ParseDuration(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("duration %q must use Go units (for example 90m or 1h30m): %w", value, err)
	}
	if duration < time.Second {
		return 0, fmt.Errorf("duration must be at least 1s")
	}
	return duration, nil
}
