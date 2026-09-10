package main

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func firewallPermits(plan firewallPlan, address string) bool {
	a := netip.MustParseAddr(address)
	for _, target := range plan.Blocked {
		p, _ := firewallPrefix(target)
		if p.Contains(a) {
			return false
		}
	}
	if !plan.Allowlist {
		return true
	}
	for _, target := range plan.Allowed {
		p, _ := firewallPrefix(target)
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func TestFirewallPoliciesIntersectNetworksAndUnionDenials(t *testing.T) {
	a := firewallPlan{Allowlist: true, Allowed: []string{"192.0.2.0/24", "2001:db8::/32"}, Blocked: []string{"192.0.2.129/32"}}
	b := firewallPlan{Allowlist: true, Allowed: []string{"192.0.2.128/25", "2001:db8:1::/48"}, Blocked: []string{"2001:db8:1::7/128"}}
	combined := firewallRestrict(a, b)
	for _, item := range []struct {
		address string
		want    bool
	}{
		{"192.0.2.128", true}, {"192.0.2.129", false}, {"192.0.2.127", false},
		{"2001:db8:1::6", true}, {"2001:db8:1::7", false}, {"2001:db8:2::1", false},
	} {
		if got := firewallPermits(combined, item.address); got != item.want {
			t.Errorf("%s permitted=%v, want %v", item.address, got, item.want)
		}
	}
	if got := firewallRestrict(b, a); !reflect.DeepEqual(got, combined) {
		t.Errorf("policy order changed restrictions: %#v vs %#v", got, combined)
	}
}

func TestFirewallDisjointAllowlistsDenyEverything(t *testing.T) {
	plan := firewallRestrict(firewallPlan{Allowlist: true, Allowed: []string{"192.0.2.0/24"}}, firewallPlan{Allowlist: true, Allowed: []string{"198.51.100.0/24"}})
	if !plan.Allowlist || len(plan.Allowed) != 0 {
		t.Fatalf("disjoint allowlists did not remain deny-all: %#v", plan)
	}
	if firewallPermits(plan, "192.0.2.1") || firewallPermits(plan, "198.51.100.1") {
		t.Fatal("disjoint allowlists permitted a member of only one policy")
	}
}

func TestDomainBlockUpgradePreservesExplicitNetworkBlocks(t *testing.T) {
	dir := t.TempDir()
	// An older installation retained a shared address resolved for a domain.
	legacy := `{"cache":{"blocked.invalid":["192.0.2.7/32"]},"plan":{"blocked":["192.0.2.7/32","198.51.100.0/24"]},"hosts":["blocked.invalid"]}`
	if err := os.WriteFile(filepath.Join(dir, "firewall.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	fw, err := NewFirewall(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan, domains, err := fw.resolve([]Policy{{Mode: "blocklist", Hosts: []string{
		"blocked.invalid", "198.51.100.0/24", "2001:db8::7",
	}}})
	if err != nil {
		t.Fatalf("domain blocking must not depend on working DNS: %v", err)
	}
	if !firewallPermits(plan, "192.0.2.7") {
		t.Fatal("upgrade retained a domain-derived block on a shared address")
	}
	if firewallPermits(plan, "198.51.100.42") || firewallPermits(plan, "2001:db8::7") {
		t.Fatal("domain cutover removed an explicit IP or CIDR block")
	}
	if !firewallPermits(plan, "2001:db8::8") {
		t.Fatal("explicit address block affected an unrelated address")
	}
	hosts, err := firewallHosts(nil, domains)
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range []string{
		"0.0.0.0 blocked.invalid\n", ":: blocked.invalid\n",
		"0.0.0.0 www.blocked.invalid\n", ":: www.blocked.invalid\n",
	} {
		if !bytes.Contains(hosts, []byte(mapping)) {
			t.Fatalf("domain no longer blocked in hosts: missing %q", mapping)
		}
	}
}

func TestDomainBlockDoesNotDenySharedAllowlistedAddress(t *testing.T) {
	fw, err := NewFirewall(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := fw.resolve([]Policy{
		{Mode: "blocklist", Hosts: []string{"blocked.invalid", "192.0.2.9"}},
		{Mode: "allowlist", Hosts: []string{"192.0.2.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !firewallPermits(plan, "192.0.2.7") {
		t.Fatal("domain block overrode an allowed network destination")
	}
	if firewallPermits(plan, "192.0.2.9") || firewallPermits(plan, "198.51.100.7") {
		t.Fatal("explicit denial or allowlist enforcement was lost")
	}
}
func TestDomainPFResolvesNonExcludedDomainsAndRetainsCache(t *testing.T) {
	fw, err := NewFirewall(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	addresses := map[string]string{
		"strict.example":     "192.0.2.10/32",
		"www.strict.example": "2001:db8::10/128",
	}
	var calls []string
	fw.lookup = func(domain string) ([]string, error) {
		calls = append(calls, domain)
		address, ok := addresses[domain]
		if !ok {
			return nil, errors.New("unexpected lookup")
		}
		return []string{address}, nil
	}
	policy := Policy{
		Mode:  "blocklist",
		Hosts: []string{"strict.example", "hosts-only.example", "203.0.113.0/24"},
		DomainPF: &DomainPFConfig{
			Enabled: true,
			Exclude: []string{"hosts-only.example"},
		},
	}
	plan, domains, err := fw.resolve([]Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"strict.example", "www.strict.example"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("DNS lookups = %v, want %v", calls, want)
	}
	if want := firewallUnique([]string{"192.0.2.10/32", "2001:db8::10/128", "203.0.113.0/24"}); !reflect.DeepEqual(plan.Blocked, want) {
		t.Fatalf("PF blocks = %v, want %v", plan.Blocked, want)
	}
	if want := firewallUnique([]string{"strict.example", "www.strict.example", "hosts-only.example", "www.hosts-only.example"}); !reflect.DeepEqual(domains, want) {
		t.Fatalf("hosts domains = %v, want %v", domains, want)
	}

	fw.lookup = func(string) ([]string, error) {
		return nil, errors.New("DNS unavailable")
	}
	cached, _, err := fw.resolve([]Policy{policy})
	if err == nil {
		t.Fatal("DNS failure was not reported")
	}
	if !reflect.DeepEqual(cached, plan) {
		t.Fatalf("DNS failure lost cached PF blocks: got %+v, want %+v", cached, plan)
	}
}

func TestFirewallHostsPreservesUnrelatedSections(t *testing.T) {
	before := []byte("127.0.0.1 localhost\n# BEGIN another-app\n192.0.2.7 private.example\n# END another-app\n")
	after := []byte("# independently managed\n::1 localhost\n")
	original := append(append(append([]byte(nil), before...), []byte(hostsBegin+"\n0.0.0.0 old.example\n"+hostsEnd+"\n")...), after...)
	updated, err := firewallHosts(original, []string{"new.example", "www.new.example"})
	if err != nil {
		t.Fatal(err)
	}
	unmanaged := append(append([]byte(nil), before...), after...)
	if !bytes.HasPrefix(updated, unmanaged) {
		t.Fatalf("unrelated content changed: %s", updated)
	}
	if bytes.Contains(updated, []byte("old.example")) {
		t.Fatal("obsolete managed host remains")
	}
	for _, mapping := range []string{"0.0.0.0 new.example\n", ":: new.example\n", "0.0.0.0 www.new.example\n", ":: www.new.example\n"} {
		if !bytes.Contains(updated, []byte(mapping)) {
			t.Errorf("missing mapping %q", mapping)
		}
	}
	cleared, err := firewallHosts(updated, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cleared, unmanaged) {
		t.Fatalf("clearing changed unmanaged content: %s", cleared)
	}
}

func TestFirewallHostsRejectsAmbiguousBoundaries(t *testing.T) {
	for _, input := range []string{
		hostsBegin + "\n# another application's content\n",
		hostsEnd + "\n",
		hostsBegin + "\n" + hostsBegin + "\n" + hostsEnd + "\n",
		hostsBegin + "\n" + hostsEnd + "\n" + hostsBegin + "\n" + hostsEnd + "\n",
	} {
		if _, err := firewallHosts([]byte(input), nil); err == nil {
			t.Errorf("accepted ambiguous boundaries: %q", input)
		}
	}
}

func TestFirewallHostsIdempotentWithoutFinalNewline(t *testing.T) {
	original := []byte("127.0.0.1 localhost")
	updated, err := firewallHosts(original, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := firewallHosts(updated, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated, second) {
		t.Fatal("unchanged hosts protection would rewrite the file")
	}
	if !bytes.HasPrefix(updated, append(append([]byte(nil), original...), '\n')) {
		t.Fatal("managed section ran into existing final line")
	}
}
