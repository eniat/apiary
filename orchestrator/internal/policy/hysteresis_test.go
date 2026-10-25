package policy

import "testing"

// the profile the naive policy reverses on
func oscillating() []Snapshot {
	var out []Snapshot
	for i := range 6 {
		if i%2 == 0 {
			out = append(out, Snapshot{Live: 2, Unserved: 3})
			continue
		}
		out = append(out, Snapshot{Live: 2, Unserved: 0})
	}
	return out
}

func TestHysteresisDoesNotFlap(t *testing.T) {
	p := Hysteresis{Up: 3, Down: 0, MinLive: 1}
	if got := reversals(run(p, oscillating())); got != 0 {
		t.Errorf("got %d reversals, want 0", got)
	}
}

// the naive policy is still what it was. same input same churn
func TestThresholdStillFlapsOnTheSameProfile(t *testing.T) {
	p := Threshold{Up: 2, MinLive: 1}
	if got := reversals(run(p, oscillating())); got != 5 {
		t.Errorf("got %d reversals, want 5", got)
	}
}

// a band narrower than the swing buys nothing
func TestHysteresisTooNarrowStillFlaps(t *testing.T) {
	p := Hysteresis{Up: 2, Down: 1, MinLive: 1}
	if got := reversals(run(p, oscillating())); got != 5 {
		t.Errorf("got %d reversals, want 5", got)
	}
}

func TestHysteresisBand(t *testing.T) {
	p := Hysteresis{Up: 4, Down: 1, MinLive: 1}

	cases := []struct {
		name string
		snap Snapshot
		want Action
	}{
		{"above the up threshold", Snapshot{Live: 2, Unserved: 5}, ScaleUp},
		{"exactly on the up threshold", Snapshot{Live: 2, Unserved: 4}, Hold},
		{"inside the band", Snapshot{Live: 2, Unserved: 3}, Hold},
		{"just inside the band", Snapshot{Live: 2, Unserved: 2}, Hold},
		{"exactly on the down threshold", Snapshot{Live: 2, Unserved: 1}, ScaleDown},
		{"below the down threshold", Snapshot{Live: 2, Unserved: 0}, ScaleDown},
		{"quiet but at the floor", Snapshot{Live: 1}, Hold},
		{"quiet but busy", Snapshot{Live: 2, Sessions: 1}, Hold},
		{"busy and over the top", Snapshot{Live: 2, Sessions: 1, Unserved: 9}, ScaleUp},
		{"nothing running", Snapshot{}, Hold},
	}

	for _, c := range cases {
		if got := p.Decide(c.snap); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
