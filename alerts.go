package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// AlertConfig is optional; resolving defaults never changes the persisted config.
type AlertConfig struct {
	Enabled         bool   `json:"enabled"`
	Interval        string `json:"interval,omitempty"`
	Message         string `json:"message,omitempty"`
	SessionDuration string `json:"session_duration,omitempty"`
}

type resolvedAlertConfig struct {
	enabled  bool
	interval time.Duration
	message  string
	duration time.Duration
}

func resolveAlertConfig(cfg *AlertConfig) (resolvedAlertConfig, error) {
	r := resolvedAlertConfig{interval: 10 * time.Minute, message: "Possible activity on a distracting site. Want to start a lock-in session?", duration: time.Hour}
	if cfg == nil {
		return r, nil
	}
	r.enabled = cfg.Enabled
	if cfg.Interval != "" {
		d, err := ParseDuration(cfg.Interval)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return r, errors.New("alerts.interval must be between 1m and 24h")
		}
		r.interval = d
	}
	if cfg.SessionDuration != "" {
		d, err := ParseDuration(cfg.SessionDuration)
		if err != nil {
			return r, fmt.Errorf("alerts.session_duration: %w", err)
		}
		r.duration = d
	}
	if cfg.Message != "" {
		if !utf8.ValidString(cfg.Message) || strings.TrimSpace(cfg.Message) == "" || utf8.RuneCountInString(cfg.Message) > 500 || strings.IndexFunc(cfg.Message, unicode.IsControl) >= 0 {
			return r, errors.New("alerts.message must contain 1–500 characters without control characters")
		}
		r.message = cfg.Message
	}
	return r, nil
}

type AlertOffer struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	Duration string `json:"duration"`
	Label    string `json:"label"`
}

type AlertStatus struct {
	Enabled       bool       `json:"enabled"`
	Pending       bool       `json:"pending"`
	Permission    string     `json:"permission"`
	LastCheck     *time.Time `json:"last_check,omitempty"`
	NextCheck     *time.Time `json:"next_check,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	DeliveryError string     `json:"delivery_error,omitempty"`
	LastMatch     *bool      `json:"last_match,omitempty"`
}

type alertSampleResult struct {
	generation uint64
	matched    bool
	err        error
}

// The worker returns only a boolean, never endpoints or browsing history.
type AlertManager struct {
	mu           sync.Mutex
	owner        int
	config       resolvedAlertConfig
	policy       Policy
	generation   uint64
	next         time.Time
	suppressed   bool
	running      bool
	cancel       context.CancelFunc
	results      chan alertSampleResult
	sample       func(context.Context, int, Policy) (bool, error)
	offer        *AlertOffer
	expires      time.Time
	acknowledged bool
	status       AlertStatus
}

func NewAlertManager(owner int) *AlertManager {
	return &AlertManager{owner: owner, results: make(chan alertSampleResult, 1), sample: collectAlertSample, status: AlertStatus{Permission: "unknown"}}
}

func (m *AlertManager) invalidate() {
	m.generation++
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.offer = nil
	m.acknowledged = false
	m.expires = time.Time{}
}

func (m *AlertManager) Configure(cfg Config, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidate()
	resolved, err := resolveAlertConfig(cfg.Alerts)
	if err != nil {
		resolved.enabled = false
	}
	m.config = resolved
	m.policy = snapshotPolicy(cfg)
	m.next = now.Add(resolved.interval)
	m.suppressed = false
	m.status = AlertStatus{Enabled: resolved.enabled, Permission: m.status.Permission}
	if err != nil {
		m.status.LastError = err.Error()
	}
	if resolved.enabled {
		next := m.next
		m.status.NextCheck = &next
	}
}

// A break suspends enforcement, not the session; it never permits reminders.
func alertSessionActive(state State, now time.Time) bool {
	for _, session := range state.Sessions {
		if now.Before(session.End) {
			return true
		}
	}
	return false
}

// refresh runs under mu and does not start work. It also gates every IPC action.
func (m *AlertManager) refresh(state State, now time.Time) {
	blocked := !m.config.enabled || alertSessionActive(state, now)
	if blocked {
		if !m.suppressed {
			m.invalidate()
		}
		m.suppressed = true
		m.status.NextCheck = nil
	} else if m.suppressed {
		m.suppressed = false
		m.next = now.Add(m.config.interval)
		next := m.next
		m.status.NextCheck = &next
	}
	if m.offer != nil && !now.Before(m.expires) {
		m.offer = nil
		m.acknowledged = false
	}
	select {
	case result := <-m.results:
		m.running = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		if blocked || result.generation != m.generation {
			return
		}
		if result.err != nil {
			m.status.LastError = result.err.Error()
			m.status.LastMatch = nil
			return
		}
		m.status.LastError = ""
		matched := result.matched
		m.status.LastMatch = &matched
		if !matched || !now.Before(m.next) {
			return
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			m.status.LastError = "cannot generate notification action identifier"
			return
		}
		m.offer = &AlertOffer{ID: hex.EncodeToString(random[:]), Message: m.config.message, Duration: m.config.duration.String(), Label: alertActionLabel(m.config.duration)}
		m.expires = m.next
		m.acknowledged = false
	default:
	}
}

func alertActionLabel(duration time.Duration) string {
	if duration%time.Hour == 0 {
		return fmt.Sprintf("Start %d-hour lock-in", duration/time.Hour)
	}
	if duration%time.Minute == 0 {
		return fmt.Sprintf("Start %d-minute lock-in", duration/time.Minute)
	}
	return "Start " + duration.String() + " lock-in"
}

func (m *AlertManager) Tick(state State, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh(state, now)
	if m.suppressed || m.running || now.Before(m.next) {
		return
	}
	m.next = now.Add(m.config.interval)
	next, checked := m.next, now
	m.status.NextCheck, m.status.LastCheck = &next, &checked
	m.status.LastMatch = nil
	// Reserve one second for exec's bounded pipe-drain cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 19*time.Second)
	m.cancel = cancel
	m.running = true
	generation, owner, policy, sample := m.generation, m.owner, m.policy, m.sample
	go func() {
		defer cancel()
		matched, err := sample(ctx, owner, policy)
		if ctx.Err() != nil {
			matched, err = false, errors.New("connection snapshot exceeded its time limit or was cancelled")
		}
		m.results <- alertSampleResult{generation: generation, matched: matched, err: err}
	}()
}

func (m *AlertManager) Poll(state State, now time.Time, permission, ackID, deliveryError string) *AlertOffer {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh(state, now)
	switch permission {
	case "not_determined", "denied", "authorized", "provisional":
		m.status.Permission = permission
	default:
		m.status.Permission = "unknown"
	}
	if m.offer != nil && ackID == m.offer.ID {
		// A failed offer is not redelivered endlessly. A later interval may offer
		// again; this one remains actionable only after successful delivery.
		m.acknowledged = true
		if deliveryError != "" {
			m.status.DeliveryError = "native notification delivery failed"
			m.offer = nil
		} else {
			m.status.DeliveryError = ""
		}
	}
	if m.offer == nil || m.acknowledged || (m.status.Permission != "authorized" && m.status.Permission != "provisional") {
		return nil
	}
	offer := *m.offer
	return &offer
}

func (m *AlertManager) Start(state State, now time.Time, id string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh(state, now)
	if m.offer == nil || id == "" || m.offer.ID != id {
		return 0, errors.New("this reminder is no longer available; start a session with lockin instead")
	}
	return m.config.duration, nil
}

func (m *AlertManager) Consume(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.offer != nil && m.offer.ID == id {
		m.offer = nil
		m.acknowledged = false
	}
}

func (m *AlertManager) Status() AlertStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Pending = m.offer != nil
	if status.LastCheck != nil {
		v := *status.LastCheck
		status.LastCheck = &v
	}
	if status.NextCheck != nil {
		v := *status.NextCheck
		status.NextCheck = &v
	}
	if status.LastMatch != nil {
		v := *status.LastMatch
		status.LastMatch = &v
	}
	return status
}

type alertConnection struct {
	protocol string
	local    netip.AddrPort
	remote   netip.AddrPort
}

// lsof supplies f boundaries with -F Pn; TCP is prefiltered to ESTABLISHED.
// UDP must have a remote endpoint. An optional TST field is also respected.
func parseAlertConnections(text string) ([]alertConnection, error) {
	var connections []alertConnection
	var protocol, name, state string
	flush := func() error {
		if protocol != "UDP" && (protocol != "TCP" || (state != "" && state != "ESTABLISHED")) {
			return nil
		}
		left, right, connected := strings.Cut(name, "->")
		if !connected {
			return nil
		}
		local, err := parseAlertEndpoint(left)
		if err != nil {
			return errors.New("connection snapshot contained an invalid local endpoint")
		}
		remote, err := parseAlertEndpoint(right)
		if err != nil {
			return errors.New("connection snapshot contained an invalid remote endpoint")
		}
		connections = append(connections, alertConnection{protocol: protocol, local: local, remote: remote})
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'p', 'f':
			if err := flush(); err != nil {
				return nil, err
			}
			protocol, name, state = "", "", ""
		case 'P':
			// P also delimits files on lsof versions omitting implicit f.
			if err := flush(); err != nil {
				return nil, err
			}
			protocol, name, state = line[1:], "", ""
		case 'n':
			name = line[1:]
		case 'T':
			if strings.HasPrefix(line, "TST=") {
				state = strings.TrimPrefix(line, "TST=")
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return connections, nil
}

func parseAlertEndpoint(text string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(text))
	if err != nil || endpoint.Port() == 0 {
		return netip.AddrPort{}, errors.New("invalid numeric endpoint")
	}
	return netip.AddrPortFrom(endpoint.Addr().WithZone("").Unmap(), endpoint.Port()), nil
}

func alertConnectionMatches(connection alertConnection, policy Policy, targets []netip.Prefix) bool {
	address := connection.remote.Addr()
	if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if policy.Mode == "allowlist" {
		// Snapshot alerts deliberately exclude local infrastructure, although PF
		// still enforces the configured allowlist there. ICMP is not sampled.
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLinkLocalUnicast() || connection.remote.Port() == 53 {
			return false
		}
		if connection.protocol == "UDP" && ((address.Is4() && connection.local.Port() == 68 && connection.remote.Port() == 67) || (address.Is6() && connection.local.Port() == 546 && connection.remote.Port() == 547)) {
			return false
		}
	}
	inside := false
	for _, target := range targets {
		if target.Contains(address) {
			inside = true
			break
		}
	}
	if policy.Mode == "allowlist" {
		return !inside
	}
	return inside
}

// All subprocess output is transient and bounded. Errors deliberately do not
// embed command output, hostnames, or connection endpoints in daemon status.
type alertOutput struct {
	bytes.Buffer
}

func (out *alertOutput) Write(data []byte) (int, error) {
	if out.Len()+len(data) > 4<<20 {
		return 0, errors.New("snapshot output limit exceeded")
	}
	return out.Buffer.Write(data)
}

func alertCommand(ctx context.Context, path string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.WaitDelay = time.Second
	var stdout, stderr alertOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		// lsof exits 1 when its selection contains no open connections.
		var exit *exec.ExitError
		if path == "/usr/sbin/lsof" && errors.As(err, &exit) && exit.ExitCode() == 1 && stdout.Len() == 0 && stderr.Len() == 0 && ctx.Err() == nil {
			return "", nil
		}
		return "", errors.New("connection snapshot command failed")
	}
	if stderr.Len() != 0 {
		return "", errors.New("connection snapshot command reported an incomplete result")
	}
	return stdout.String(), nil
}

// This follows firewallLookup's direct DNS semantics, but all A/AAAA queries
// share the sampler's hard deadline. It neither reads nor writes PF recovery
// caches; getaddrinfo would incorrectly consult our own blocking hosts entries.
func alertLookup(ctx context.Context, domain string) ([]netip.Prefix, error) {
	var addresses []netip.Prefix
	missing := 0
	for _, family := range []string{"A", "AAAA"} {
		text, err := alertCommand(ctx, "/usr/bin/dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", domain, family)
		if err != nil {
			return nil, errors.New("alert DNS resolution failed")
		}
		if strings.Contains(text, "status: NXDOMAIN,") {
			missing++
			continue
		}
		if !strings.Contains(text, "status: NOERROR,") {
			return nil, errors.New("alert DNS resolution did not return NOERROR")
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || (fields[3] != "A" && fields[3] != "AAAA") {
				continue
			}
			address, err := netip.ParseAddr(fields[4])
			if err != nil || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
				return nil, errors.New("alert DNS resolution returned an unusable address")
			}
			address = address.Unmap()
			addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	if missing == 2 {
		return nil, firewallDNSMissing
	}
	if missing != 0 || len(addresses) == 0 {
		return nil, errors.New("alert DNS resolution returned incomplete addresses")
	}
	return addresses, nil
}

func resolveAlertTargets(ctx context.Context, policy Policy, lookup func(context.Context, string) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	var targets []netip.Prefix
	seen := make(map[string]bool)
	for _, host := range policy.Hosts {
		if ctx.Err() != nil {
			return nil, errors.New("alert target resolution was cancelled")
		}
		if prefix, err := netip.ParsePrefix(host); err == nil {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			targets = append(targets, prefix.Masked())
			continue
		}
		if address, err := netip.ParseAddr(host); err == nil {
			address = address.Unmap()
			targets = append(targets, netip.PrefixFrom(address, address.BitLen()))
			continue
		}
		for index, domain := range firewallDomains(host) {
			if seen[domain] {
				continue
			}
			seen[domain] = true
			addresses, err := lookup(ctx, domain)
			if err != nil {
				if index > 0 && errors.Is(err, firewallDNSMissing) {
					continue
				}
				// In particular, a partially resolved allowlist must not label
				// an actually allowed address as distracting.
				return nil, errors.New("alert targets could not be fully resolved; snapshot suppressed")
			}
			targets = append(targets, addresses...)
		}
	}
	return targets, nil
}

func collectAlertSample(ctx context.Context, owner int, policy Policy) (bool, error) {
	if owner < 0 {
		return false, errors.New("connection snapshot requires an installed owner UID")
	}
	text, err := alertCommand(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(owner), "-i", "-sTCP:ESTABLISHED", "-F", "Pn")
	if err != nil {
		return false, err
	}
	connections, err := parseAlertConnections(text)
	if err != nil {
		return false, err
	}
	if len(connections) == 0 {
		return false, nil
	}
	targets, err := resolveAlertTargets(ctx, policy, alertLookup)
	if err != nil {
		return false, err
	}
	for _, connection := range connections {
		if alertConnectionMatches(connection, policy, targets) {
			return true, nil
		}
	}
	return false, nil
}
