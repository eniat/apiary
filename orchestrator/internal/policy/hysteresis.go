package policy

// separate thresholds with a gap between them
// the gap has to be wider than the noise or it flaps anyway
type Hysteresis struct {
	Up      int // unserved above this scales up
	Down    int // unserved at or below this allows a scale down
	MinLive int
}

func (h Hysteresis) Decide(s Snapshot) Action {
	if s.Unserved > h.Up {
		return ScaleUp
	}
	// inside the band nothing moves
	if s.Unserved > h.Down {
		return Hold
	}
	if s.Live > h.MinLive && s.Sessions == 0 {
		return ScaleDown
	}
	return Hold
}
