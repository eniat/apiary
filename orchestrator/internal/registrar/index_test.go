package registrar

import (
	"net"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func fixture(ages map[string]time.Duration, ids map[string]string) *Registrar {
	r := &Registrar{srcs: map[string]bind{}}
	for s, age := range ages {
		r.srcs[s] = bind{id: ids[s], seen: now.Add(-age)}
	}
	return r
}

func TestSourcesFor(t *testing.T) {
	r := fixture(
		map[string]time.Duration{"10.10.10.20": 0, "10.10.10.21": 0, "10.10.10.22": 0},
		map[string]string{"10.10.10.20": "a", "10.10.10.21": "a", "10.10.10.22": "b"},
	)

	if got := len(r.SourcesFor("a")); got != 2 {
		t.Errorf("got %d sources for a, want 2", got)
	}
	if got := len(r.SourcesFor("b")); got != 1 {
		t.Errorf("got %d sources for b, want 1", got)
	}
	if got := len(r.SourcesFor("gone")); got != 0 {
		t.Errorf("got %d sources for gone, want 0", got)
	}
}

func TestSourcesForParses(t *testing.T) {
	r := fixture(map[string]time.Duration{"10.10.10.20": 0}, map[string]string{"10.10.10.20": "a"})
	got := r.SourcesFor("a")
	if len(got) != 1 || !got[0].Equal(net.ParseIP("10.10.10.20")) {
		t.Errorf("got %v, want [10.10.10.20]", got)
	}
}

func TestBound(t *testing.T) {
	ttl := 5 * time.Minute
	r := fixture(
		map[string]time.Duration{"10.10.10.20": time.Minute, "10.10.10.21": time.Hour},
		map[string]string{"10.10.10.20": "fresh", "10.10.10.21": "stale"},
	)

	cases := []struct {
		id   string
		want bool
	}{
		{"fresh", true},
		{"stale", false},
		{"unknown", false},
	}
	for _, c := range cases {
		if got := r.Bound(c.id, now, ttl); got != c.want {
			t.Errorf("%s: got %v, want %v", c.id, got, c.want)
		}
	}
}

func TestBoundExactlyAtTheTTL(t *testing.T) {
	r := fixture(map[string]time.Duration{"10.10.10.20": time.Minute}, map[string]string{"10.10.10.20": "a"})
	if !r.Bound("a", now, time.Minute) {
		t.Error("a binding exactly at the ttl should still hold")
	}
}

func TestRefreshRevivesABinding(t *testing.T) {
	ttl := time.Minute
	r := fixture(map[string]time.Duration{"10.10.10.20": time.Hour}, map[string]string{"10.10.10.20": "a"})

	if r.Bound("a", now, ttl) {
		t.Fatal("want stale before the refresh")
	}
	r.Refresh("a", now)
	if !r.Bound("a", now, ttl) {
		t.Error("want bound after the refresh")
	}
}

func TestRefreshLeavesOthersAlone(t *testing.T) {
	ttl := time.Minute
	r := fixture(
		map[string]time.Duration{"10.10.10.20": time.Hour, "10.10.10.21": time.Hour},
		map[string]string{"10.10.10.20": "a", "10.10.10.21": "b"},
	)

	r.Refresh("a", now)
	if r.Bound("b", now, ttl) {
		t.Error("b should still be stale")
	}
}
