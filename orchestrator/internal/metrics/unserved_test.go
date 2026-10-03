package metrics

import "testing"

func TestDelta(t *testing.T) {
	cases := []struct {
		name string
		last uint64
		now  uint64
		want uint64
	}{
		{"climbing", 10, 14, 4},
		{"flat", 14, 14, 0},
		{"map reset", 14, 2, 2},
		{"reset to zero", 14, 0, 0},
	}
	for _, c := range cases {
		if got := delta(c.last, c.now); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}
