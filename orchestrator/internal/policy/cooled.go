package policy

import "time"

// Cooled refuses an action that comes too soon after the last one
// scaling up late loses an attacker and scaling down late only costs a container
// so the two intervals are separate and up is usually zero
type Cooled struct {
	Decider
	Up   time.Duration // minimum gap before another scale up
	Down time.Duration // minimum gap before another scale down
}

func (c Cooled) Decide(s Snapshot) Action {
	a := c.Decider.Decide(s)
	// nothing has acted yet so the first one is free
	if a == Hold || s.LastAction.IsZero() {
		return a
	}

	// any action resets both clocks. that is what stops alternation
	since := s.Now.Sub(s.LastAction)
	switch a {
	case ScaleUp:
		if since < c.Up {
			return Hold
		}
	case ScaleDown:
		if since < c.Down {
			return Hold
		}
	}
	return a
}
