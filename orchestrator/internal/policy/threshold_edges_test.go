package policy

import (
	"testing"
	"time"
)

// one snapshot per tick
func run(d Decider, snaps []Snapshot) []Action {
	out := make([]Action, len(snaps))
	for i, s := range snaps {
		out[i] = d.Decide(s)
	}
	return out
}

// reversals between up and down with holds ignored
func reversals(as []Action) int {
	n, last := 0, Hold
	for _, a := range as {
		if a == Hold {
			continue
		}
		if last != Hold && a != last {
			n++
		}
		last = a
	}
	return n
}

func TestThresholdEdges(t *testing.T) {
	p := Threshold{Up: 2, MinLive: 1}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		snap Snapshot
		want Action
	}{
		{"exactly on the threshold", Snapshot{Live: 1, Unserved: 2}, Hold},
		{"one over the threshold", Snapshot{Live: 1, Unserved: 3}, ScaleUp},
		{"nothing live and nothing unserved", Snapshot{}, Hold},
		{"nothing live but flows unserved", Snapshot{Unserved: 9}, ScaleUp},
		{"warm pool exhausted", Snapshot{Live: 3, Warm: 0, Unserved: 9}, ScaleUp},
		{"every honeypot busy", Snapshot{Live: 3, Sessions: 3}, Hold},
		{"one session pins the whole fleet", Snapshot{Live: 9, Sessions: 1}, Hold},
		{"stale snapshot decides the same", Snapshot{Now: old, Live: 2}, ScaleDown},
	}

	for _, c := range cases {
		if got := p.Decide(c.snap); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// documents the defect. hysteresis drives this to zero
func TestThresholdFlaps(t *testing.T) {
	p := Threshold{Up: 2, MinLive: 1}

	var snaps []Snapshot
	for i := range 6 {
		if i%2 == 0 {
			snaps = append(snaps, Snapshot{Live: 2, Unserved: 3})
			continue
		}
		snaps = append(snaps, Snapshot{Live: 2, Unserved: 0})
	}

	got := reversals(run(p, snaps))
	if got != 5 {
		t.Errorf("got %d reversals, want 5", got)
	}
}
