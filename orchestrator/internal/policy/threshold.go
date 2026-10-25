package policy

// one threshold with no hysteresis and no cooldown
type Threshold struct {
	Up      int // unserved flows that trigger a scale up
	MinLive int // floor so the fleet never empties
}

// a single reading decides. nothing is remembered between ticks
func (t Threshold) Decide(s Snapshot) Action {
	if s.Unserved > t.Up {
		return ScaleUp
	}
	if s.Live > t.MinLive && s.Sessions == 0 {
		return ScaleDown
	}
	return Hold
}
