package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const firewallAnchor = "com.apple/000.lockin"
const hostsBegin = "# BEGIN lockin managed hosts"
const hostsEnd = "# END lockin managed hosts"

// firewallPlan is already resolved: intersecting address ranges, rather than
// domain names, gives overlapping allowlists their actual network meaning.
type firewallPlan struct {
	Blocked   []string `json:"blocked,omitempty"`
	Allowed   []string `json:"allowed,omitempty"`
	Allowlist bool     `json:"allowlist"`
}

type firewallRecovery struct {
	Cache      map[string][]string `json:"cache"`
	AllowCache map[string][]string `json:"allow_cache"`
	Plan       firewallPlan        `json:"plan"`
	Hosts      []string            `json:"hosts,omitempty"`
	Token      string              `json:"token,omitempty"`
	Boot       string              `json:"boot,omitempty"`
	Snapshot   string              `json:"snapshot,omitempty"`
}

// Firewall is single-owner, like the daemon. Nothing is disabled on shutdown.
// A root user can always bypass this mechanism; it is not a security boundary.
type Firewall struct {
	dir      string
	recovery firewallRecovery
}

func NewFirewall(stateDir string) (*Firewall, error) {
	f := &Firewall{dir: stateDir}
	data, err := os.ReadFile(filepath.Join(stateDir, "firewall.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &f.recovery); err != nil {
			return nil, fmt.Errorf("read firewall recovery: %w", err)
		}
	}
	if f.recovery.Cache == nil {
		f.recovery.Cache = make(map[string][]string)
	}
	if f.recovery.AllowCache == nil {
		f.recovery.AllowCache = make(map[string][]string)
	}
	return f, nil
}

func firewallCommand(input []byte, binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", binary, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	// pfctl prints its enable token to stderr, unlike its inspection output.
	if binary == "/sbin/pfctl" && len(args) == 1 && args[0] == "-E" {
		return stdout.String() + stderr.String(), nil
	}
	return stdout.String(), nil
}

func (f *Firewall) save() error {
	data, err := json.MarshalIndent(f.recovery, "", "  ")
	if err != nil {
		return err
	}
	return firewallAtomic(filepath.Join(f.dir, "firewall.json"), append(data, '\n'), 0600, -1, -1)
}

func firewallAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".lockin-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if uid >= 0 {
		if err = tmp.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
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

func firewallUnique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, s := range values {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func firewallPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func firewallIntersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		p, _ := firewallPrefix(x)
		for _, y := range b {
			q, _ := firewallPrefix(y)
			if !p.Overlaps(q) {
				continue
			}
			if p.Bits() >= q.Bits() {
				out = append(out, p.String())
			} else {
				out = append(out, q.String())
			}
		}
	}
	return firewallUnique(out)
}

func firewallRestrict(a, b firewallPlan) firewallPlan {
	out := firewallPlan{Blocked: firewallUnique(append(append([]string(nil), a.Blocked...), b.Blocked...)), Allowlist: a.Allowlist || b.Allowlist}
	switch {
	case a.Allowlist && b.Allowlist:
		out.Allowed = firewallIntersect(a.Allowed, b.Allowed)
	case a.Allowlist:
		out.Allowed = append([]string(nil), a.Allowed...)
	case b.Allowlist:
		out.Allowed = append([]string(nil), b.Allowed...)
	}
	return out
}

var firewallDNSMissing = errors.New("DNS name does not exist")

// dig speaks DNS directly, never getaddrinfo(/etc/hosts). Its default server is
// the system resolv.conf server. macOS scoped/split DNS is not reproduced.
func firewallLookup(domain string) ([]string, error) {
	var addresses []string
	var failures []error
	missing := 0
	for _, family := range []string{"A", "AAAA"} {
		text, err := firewallCommand(nil, "/usr/bin/dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", domain, family)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if strings.Contains(text, "status: NXDOMAIN,") {
			missing++
			continue
		}
		if !strings.Contains(text, "status: NOERROR,") {
			failures = append(failures, fmt.Errorf("DNS %s %s did not return NOERROR", domain, family))
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || (fields[3] != "A" && fields[3] != "AAAA") {
				continue
			}
			a, err := netip.ParseAddr(fields[4])
			if err != nil {
				continue
			}
			a = a.Unmap()
			if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				failures = append(failures, fmt.Errorf("DNS %s returned unsafe address %s", domain, a))
				continue
			}
			addresses = append(addresses, netip.PrefixFrom(a, a.BitLen()).String())
		}
	}
	if missing == 2 {
		return nil, fmt.Errorf("%s: %w", domain, firewallDNSMissing)
	}
	if len(addresses) == 0 {
		failures = append(failures, fmt.Errorf("DNS %s has no usable IP addresses (hosts protection only for a new blocked domain)", domain))
	}
	return firewallUnique(addresses), errors.Join(failures...)
}

func (f *Firewall) resolve(policies []Policy) (firewallPlan, []string, error) {
	var plan firewallPlan
	var hosts []string
	var failures []error
	type lookup struct {
		addresses []string
		err       error
	}
	resolved := make(map[string]lookup)
	for _, policy := range policies {
		part := firewallPlan{Allowlist: policy.Mode == "allowlist"}
		if policy.Mode != "blocklist" && !part.Allowlist {
			return plan, hosts, fmt.Errorf("invalid firewall policy mode %q", policy.Mode)
		}
		var targets []string
		for _, host := range policy.Hosts {
			if p, err := firewallPrefix(host); err == nil {
				targets = append(targets, p.String())
				continue
			}
			for index, domain := range firewallDomains(host) {
				if !part.Allowlist {
					hosts = append(hosts, domain)
				}
				result, seen := resolved[domain]
				if !seen {
					result.addresses, result.err = firewallLookup(domain)
					resolved[domain] = result
					f.recovery.Cache[domain] = firewallUnique(append(append([]string(nil), f.recovery.Cache[domain]...), result.addresses...))
					if result.err == nil || errors.Is(result.err, firewallDNSMissing) {
						f.recovery.AllowCache[domain] = result.addresses
					}
				}
				if result.err != nil && !(index > 0 && errors.Is(result.err, firewallDNSMissing)) {
					failures = append(failures, result.err)
				}
				if part.Allowlist {
					targets = append(targets, f.recovery.AllowCache[domain]...)
				} else {
					targets = append(targets, f.recovery.Cache[domain]...)
				}
			}
		}
		if part.Allowlist {
			part.Allowed = firewallUnique(targets)
		} else {
			part.Blocked = firewallUnique(targets)
		}
		plan = firewallRestrict(plan, part)
	}
	return plan, firewallUnique(hosts), errors.Join(failures...)
}

func firewallDomains(host string) []string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasPrefix(host, "www.") {
		return []string{host}
	}
	return []string{host, "www." + host}
}

func firewallRules(plan firewallPlan) string {
	var b strings.Builder
	if len(plan.Blocked) > 0 {
		fmt.Fprintf(&b, "table <lockin_blocked> const { %s }\n", strings.Join(plan.Blocked, ", "))
	}
	if plan.Allowlist {
		fmt.Fprintf(&b, "table <lockin_allowed> const { %s }\n", strings.Join(plan.Allowed, ", "))
	}
	if len(plan.Blocked) > 0 {
		b.WriteString("block drop out quick on ! lo0 to <lockin_blocked>\nblock drop in quick on ! lo0 from <lockin_blocked>\n")
	}
	if plan.Allowlist {
		// Only infrastructure is passed here; permitted destinations otherwise
		// fall through, so unrelated PF rules remain authoritative for them.
		b.WriteString("pass out quick on ! lo0 proto tcp to any port 53 flags any no state\n")
		b.WriteString("pass out quick on ! lo0 proto udp to any port 53 no state\n")
		b.WriteString("pass out quick on ! lo0 inet proto udp from any port 68 to any port 67 no state\n")
		b.WriteString("pass out quick on ! lo0 inet6 proto udp from any port 546 to any port 547 no state\n")
		b.WriteString("pass out quick on ! lo0 inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state\n")
		b.WriteString("block drop out quick on ! lo0 to ! <lockin_allowed>\n")
	}
	return b.String()
}

// Managed lines are removed only between a single, complete pair of exact
// marker lines. Malformed/duplicate boundaries fail closed instead of eating
// another application's section. All unmanaged bytes stay byte-for-byte.
func firewallHosts(original []byte, domains []string) ([]byte, error) {
	lines := bytes.SplitAfter(original, []byte("\n"))
	start, end := -1, -1
	for i, line := range lines {
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		switch text {
		case hostsBegin:
			if start >= 0 || end >= 0 {
				return nil, errors.New("duplicate or reversed lockin hosts markers")
			}
			start = i
		case hostsEnd:
			if start < 0 || end >= 0 {
				return nil, errors.New("unmatched lockin hosts marker")
			}
			end = i
		}
	}
	if start >= 0 && end < 0 {
		return nil, errors.New("unterminated lockin hosts section")
	}
	var out []byte
	if start < 0 {
		out = append(out, original...)
	} else {
		out = append(out, bytes.Join(lines[:start], nil)...)
		out = append(out, bytes.Join(lines[end+1:], nil)...)
	}
	if len(domains) == 0 {
		return out, nil
	}
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, hostsBegin+"\n"...)
	for _, domain := range firewallUnique(append([]string(nil), domains...)) {
		out = append(out, "0.0.0.0 "+domain+"\n:: "+domain+"\n"...)
	}
	return append(out, hostsEnd+"\n"...), nil
}

func firewallWriteHosts(domains []string) error {
	const path = "/etc/hosts"
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("/etc/hosts is not a regular file; refusing to replace it")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, err := firewallHosts(original, domains)
	if err != nil {
		return err
	}
	if bytes.Equal(original, next) {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine /etc/hosts ownership")
	}
	if err = firewallAtomic(path, next, info.Mode().Perm(), int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}
	if _, err = firewallCommand(nil, "/usr/bin/dscacheutil", "-flushcache"); err != nil {
		return err
	}
	_, err = firewallCommand(nil, "/usr/bin/killall", "-HUP", "mDNSResponder")
	return err
}

func firewallActive(plan firewallPlan) bool { return plan.Allowlist || len(plan.Blocked) > 0 }

func firewallLoad(plan firewallPlan) error {
	rules := []byte(firewallRules(plan))
	if _, err := firewallCommand(rules, "/sbin/pfctl", "-n", "-a", firewallAnchor, "-f", "-"); err != nil {
		return fmt.Errorf("validate PF anchor: %w", err)
	}
	_, err := firewallCommand(rules, "/sbin/pfctl", "-a", firewallAnchor, "-f", "-")
	return err
}

func firewallSnapshot(plan firewallPlan) (string, error) {
	rules, err := firewallCommand(nil, "/sbin/pfctl", "-a", firewallAnchor, "-s", "rules")
	if err != nil {
		return "", err
	}
	for _, table := range []struct {
		name    string
		present bool
	}{{"lockin_blocked", len(plan.Blocked) > 0}, {"lockin_allowed", plan.Allowlist}} {
		if !table.present {
			continue
		}
		contents, err := firewallCommand(nil, "/sbin/pfctl", "-a", firewallAnchor, "-t", table.name, "-T", "show")
		if err != nil {
			return "", err
		}
		rules += "\n" + table.name + "\n" + contents
	}
	return rules, nil
}

func firewallEvict(plan firewallPlan) error {
	if plan.Allowlist {
		// macOS cannot selectively kill the complement of an address set.
		// This disrupts other PF users' connections, but never their rules.
		_, err := firewallCommand(nil, "/sbin/pfctl", "-F", "states")
		return err
	}
	for _, target := range plan.Blocked {
		p, _ := firewallPrefix(target)
		any := "0.0.0.0/0"
		if p.Addr().Is6() {
			any = "::/0"
		}
		if _, err := firewallCommand(nil, "/sbin/pfctl", "-k", any, "-k", target); err != nil {
			return err
		}
		if _, err := firewallCommand(nil, "/sbin/pfctl", "-k", target); err != nil {
			return err
		}
	}
	return nil
}

var firewallTokenPattern = regexp.MustCompile(`(?i)token\s*:\s*([0-9]+)`)

func (f *Firewall) enable() error {
	boot, err := firewallCommand(nil, "/usr/sbin/sysctl", "-n", "kern.boottime")
	if err != nil {
		return err
	}
	references, err := firewallCommand(nil, "/sbin/pfctl", "-s", "References")
	if err != nil {
		return err
	}
	owned := false
	if f.recovery.Boot == boot && f.recovery.Token != "" {
		for _, field := range strings.Fields(references) {
			if strings.Trim(field, ",:") == f.recovery.Token {
				owned = true
				break
			}
		}
	}
	if owned {
		status, err := firewallCommand(nil, "/sbin/pfctl", "-s", "info")
		if err != nil {
			return err
		}
		if strings.Contains(status, "Status: Enabled") {
			return nil
		}
		// Retain the existing reference if another root process disabled PF.
		_, err = firewallCommand(nil, "/sbin/pfctl", "-e")
		return err
	}
	text, err := firewallCommand(nil, "/sbin/pfctl", "-E")
	if err != nil {
		return err
	}
	match := firewallTokenPattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return fmt.Errorf("PF enabled but no reference token returned: %s", strings.TrimSpace(text))
	}
	if _, err := strconv.ParseUint(match[1], 10, 64); err != nil {
		return err
	}
	f.recovery.Token, f.recovery.Boot = match[1], boot
	if err := f.save(); err != nil {
		_, releaseErr := firewallCommand(nil, "/sbin/pfctl", "-X", match[1])
		f.recovery.Token = ""
		return errors.Join(err, releaseErr)
	}
	return nil
}

func (f *Firewall) release() error {
	if f.recovery.Token == "" {
		return nil
	}
	boot, err := firewallCommand(nil, "/usr/sbin/sysctl", "-n", "kern.boottime")
	if err != nil {
		return err
	}
	if boot == f.recovery.Boot {
		references, err := firewallCommand(nil, "/sbin/pfctl", "-s", "References")
		if err != nil {
			return err
		}
		for _, field := range strings.Fields(references) {
			if strings.Trim(field, ",:") == f.recovery.Token {
				if _, err := firewallCommand(nil, "/sbin/pfctl", "-X", f.recovery.Token); err != nil {
					return err
				}
				break
			}
		}
	}
	f.recovery.Token, f.recovery.Boot = "", ""
	return f.save()
}

// A never-initialized macOS PF ruleset has no filter anchor at all. Bootstrap
// only that empty filter ruleset; -R leaves translation/dummynet rules alone.
// Nonempty third-party rulesets are never replaced to insert our attachment.
func firewallEnsureAnchor() error {
	root, err := firewallCommand(nil, "/sbin/pfctl", "-s", "rules")
	if err != nil {
		return err
	}
	if strings.TrimSpace(root) == "" {
		minimal := []byte("anchor \"com.apple/*\"\n")
		if _, err := firewallCommand(minimal, "/sbin/pfctl", "-n", "-R", "-f", "-"); err != nil {
			return err
		}
		// Narrow the race with another PF owner initializing the filter.
		root, err = firewallCommand(nil, "/sbin/pfctl", "-s", "rules")
		if err != nil {
			return err
		}
		if strings.TrimSpace(root) == "" {
			if _, err := firewallCommand(minimal, "/sbin/pfctl", "-R", "-f", "-"); err != nil {
				return err
			}
			root, err = firewallCommand(nil, "/sbin/pfctl", "-s", "rules")
			if err != nil {
				return err
			}
		}
	}
	for _, line := range strings.Split(root, "\n") {
		if strings.TrimSpace(line) == `anchor "com.apple/*" all` || strings.TrimSpace(line) == `anchor "com.apple/*"` {
			return nil
		}
	}
	return errors.New("active PF main rules lack the unconditional com.apple/* anchor; refusing to replace a nonempty global filter configuration")
}

// Apply returns an error for degraded DNS even when hosts and cached-IP
// protection are installed. A failure retains the restrictive union of the
// previous and requested plans; it never silently acknowledges an unlock.
func (f *Firewall) Apply(policies []Policy) error {
	old := f.recovery.Plan
	oldHosts := append([]string(nil), f.recovery.Hosts...)
	plan, hosts, dnsErr := f.resolve(policies)
	guard := firewallRestrict(old, plan)
	guardHosts := firewallUnique(append(append([]string(nil), oldHosts...), hosts...))
	if dnsErr != nil {
		plan, hosts = guard, guardHosts
	}
	previousSnapshot := f.recovery.Snapshot
	f.recovery.Plan, f.recovery.Hosts = guard, guardHosts
	if err := f.save(); err != nil {
		return errors.Join(dnsErr, err)
	}
	if firewallActive(plan) {
		if err := firewallEnsureAnchor(); err != nil {
			return errors.Join(dnsErr, err)
		}
	}
	fail := func(err error) error {
		// Reload the restrictive guard if the desired rules were installed
		// before a later step failed. Recovery is already durable.
		restoreErr := firewallLoad(guard)
		hostErr := firewallWriteHosts(guardHosts)
		var enableErr, evictErr error
		if firewallActive(guard) {
			enableErr = f.enable()
			if restoreErr == nil && enableErr == nil {
				evictErr = firewallEvict(guard)
			}
		}
		f.recovery.Snapshot = ""
		return errors.Join(dnsErr, err, restoreErr, hostErr, enableErr, evictErr, f.save())
	}
	if err := firewallWriteHosts(guardHosts); err != nil {
		return fail(err)
	}
	if firewallActive(plan) {
		if err := f.enable(); err != nil {
			return fail(err)
		}
	}
	changed := firewallRules(old) != firewallRules(plan)
	if !changed {
		actual, err := firewallSnapshot(plan)
		if err != nil || actual != previousSnapshot {
			changed = true
		}
	}
	if changed {
		if err := firewallLoad(plan); err != nil {
			return fail(err)
		}
		if err := firewallEvict(plan); err != nil {
			return fail(err)
		}
	}
	snapshot := previousSnapshot
	if changed {
		var err error
		snapshot, err = firewallSnapshot(plan)
		if err != nil {
			return fail(err)
		}
	}
	if err := firewallWriteHosts(hosts); err != nil {
		return fail(err)
	}
	f.recovery.Plan, f.recovery.Hosts, f.recovery.Snapshot = plan, hosts, snapshot
	if err := f.save(); err != nil {
		f.recovery.Plan, f.recovery.Hosts = guard, guardHosts
		return fail(err)
	}
	if !firewallActive(plan) {
		if err := f.release(); err != nil {
			f.recovery.Plan, f.recovery.Hosts = guard, guardHosts
			return fail(err)
		}
	}
	return dnsErr
}
