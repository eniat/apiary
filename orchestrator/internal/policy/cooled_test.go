package policy

import (
	"testing"
	"time"
)

var coolStart = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// mirrors what the loop does with LastAction between ticks
func drive(d Decider, every time.Duration, unserved []int) []Action {
	var last time.Time
	out := make([]Action, len(unserved))
	for i, u := range unserved {
		s := Snapshot{
			Now:        coolStart.Add(time.Duration(i) * every),
			Live:       3,
			Unserved:   u,
			LastAction: last,
		}
		out[i] = d.Decide(s)
		if out[i] != Hold {
			last = s.Now
		}
	}
	return out
}

func count(as []Action, want Action) int {
	n := 0
	for _, a := range as {
		if a == want {
			n++
		}
	}
	return n
}

// the guide's case. a spike on every tick must not act on every tick
func TestCooldownCapsRapidSpikes(t *testing.T) {
	spike := make([]int, 12)
	for i := range spike {
		spike[i] = 9
	}
	p := Cooled{Decider: Hysteresis{Up: 3, Down: 0, MinLive: 1}, Up: 30 * time.Second}

	// twelve ticks of five seconds spans fifty five seconds
	got := count(drive(p, 5*time.Second, spike), ScaleUp)
	if got != 2 {
		t.Errorf("got %d ups across 55s with a 30s cooldown, want 2", got)
	}
}

func TestWithoutCooldownEveryTickActs(t *testing.T) {
	spike := make([]int, 12)
	for i := range spike {
		spike[i] = 9
	}
	p := Hysteresis{Up: 3, Down: 0, MinLive: 1}

	if got := count(drive(p, 5*time.Second, spike), ScaleUp); got != 12 {
		t.Errorf("got %d ups, want 12", got)
	}
}

func TestCooldownKillsTheRemainingFlap(t *testing.T) {
	p := Cooled{Decider: Hysteresis{Up: 2, Down: 1, MinLive: 1}, Down: 30 * time.Second}
	// run does not thread LastAction between ticks so drive is the honest driver
	if got := reversals(drive(p, 5*time.Second, []int{3, 0, 3, 0, 3, 0})); got != 0 {
		t.Errorf("got %d reversals, want 0", got)
	}
}

func TestCooldownNeverInventsAnAction(t *testing.T) {
	p := Cooled{Decider: Hysteresis{Up: 3, Down: 0, MinLive: 1}, Up: time.Minute, Down: time.Minute}
	quiet := []int{2, 2, 2, 2}
	for i, a := range drive(p, 5*time.Second, quiet) {
		if a != Hold {
			t.Errorf("tick %d: got %v, want hold", i, a)
		}
	}
}

func TestCooldownEdges(t *testing.T) {
	p := Cooled{Decider: Hysteresis{Up: 3, Down: 0, MinLive: 1}, Up: 30 * time.Second, Down: 30 * time.Second}

	cases := []struct {
		name  string
		since time.Duration
		snap  Snapshot
		want  Action
	}{
		{"up just inside the window", 29 * time.Second, Snapshot{Live: 2, Unserved: 9}, Hold},
		{"up exactly at the window", 30 * time.Second, Snapshot{Live: 2, Unserved: 9}, ScaleUp},
		{"up past the window", 31 * time.Second, Snapshot{Live: 2, Unserved: 9}, ScaleUp},
		{"down just inside the window", 29 * time.Second, Snapshot{Live: 2}, Hold},
		{"down exactly at the window", 30 * time.Second, Snapshot{Live: 2}, ScaleDown},
		{"hold stays hold", time.Second, Snapshot{Live: 2, Unserved: 2}, Hold},
	}

	for _, c := range cases {
		s := c.snap
		s.Now = coolStart
		s.LastAction = coolStart.Add(-c.since)
		if got := p.Decide(s); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestZeroCooldownIsNoCooldown(t *testing.T) {
	p := Cooled{Decider: Hysteresis{Up: 3, Down: 0, MinLive: 1}}
	s := Snapshot{Now: coolStart, LastAction: coolStart.Add(-time.Millisecond), Live: 2, Unserved: 9}
	if got := p.Decide(s); got != ScaleUp {
		t.Errorf("got %v, want ScaleUp", got)
	}
}
