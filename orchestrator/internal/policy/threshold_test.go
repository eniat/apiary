package policy

import "testing"

func TestThresholdDecide(t *testing.T) {
	p := Threshold{Up: 2, MinLive: 1}

	cases := []struct {
		name string
		snap Snapshot
		want Action
	}{
		{"unserved over the line", Snapshot{Live: 1, Unserved: 3}, ScaleUp},
		{"unserved on the line", Snapshot{Live: 1, Unserved: 2}, Hold},
		{"idle above the floor", Snapshot{Live: 2}, ScaleDown},
		{"idle at the floor", Snapshot{Live: 1}, Hold},
		{"busy above the floor", Snapshot{Live: 2, Sessions: 1}, Hold},
		{"busy and unserved", Snapshot{Live: 2, Sessions: 1, Unserved: 5}, ScaleUp},
		{"nothing running", Snapshot{}, Hold},
	}

	for _, c := range cases {
		if got := p.Decide(c.snap); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
