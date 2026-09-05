package main

import (
	"bytes"
	"net/netip"
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
