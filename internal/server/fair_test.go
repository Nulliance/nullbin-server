package server

import (
	"net/netip"
	"testing"
	"time"
)

// A network pulling as fast as it can no longer takes the whole download
// budget: one that has to wait gets an equal share from the next window on
// (audit A3). The networks of one IPv6 /48 count as one (A4).
func TestFairBudgetSharesBetweenNetworks(t *testing.T) {
	const chunk = bandwidthChunk
	f := newFairBudget(64 * chunk / fairWindow.Seconds()) // 64 chunks a window
	heavy := netip.MustParseAddr("192.0.2.1")
	light := netip.MustParseAddr("198.51.100.1")
	start := time.Unix(1_000_000, 0)
	took := func(ip netip.Addr, now time.Time) int {
		n := 0
		for {
			if ok, _ := f.take(ip, now, chunk); !ok {
				return n
			}
			n++
		}
	}
	// Alone, the heavy network may use all of it, and the light one waits.
	if n := took(heavy, start); n != 64 {
		t.Fatalf("alone: %d chunks, want 64", n)
	}
	if ok, wait := f.take(light, start, chunk); ok || wait <= 0 || wait > fairWindow {
		t.Fatalf("light network while all is spent: %v, %v", ok, wait)
	}
	// Next window: two networks took part, so each gets half.
	next := start.Add(fairWindow)
	if n := took(heavy, next); n != 32 {
		t.Fatalf("heavy network in the next window: %d chunks, want 32", n)
	}
	if n := took(light, next); n != 32 {
		t.Fatalf("light network in the next window: %d chunks, want 32", n)
	}

	// Two /64s of one /48 are one network here.
	g := newFairBudget(64 * chunk / fairWindow.Seconds())
	a := netip.MustParseAddr("2001:db8:1:1::1")
	b := netip.MustParseAddr("2001:db8:1:2::1")
	for _, ip := range []netip.Addr{a, b} {
		if ok, _ := g.take(ip, start, 10*chunk); !ok {
			t.Fatalf("%v refused", ip)
		}
	}
	if n := len(g.used); n != 1 {
		t.Fatalf("two /64s of one /48 counted as %d networks", n)
	}
	for _, used := range g.used {
		if used != 20*chunk {
			t.Fatalf("the /48 used %v bytes, want both /64s' %d", used, 20*chunk)
		}
	}
}
