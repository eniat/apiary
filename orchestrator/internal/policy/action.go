package policy

func (a Action) String() string {
	switch a {
	case ScaleUp:
		return "up"
	case ScaleDown:
		return "down"
	default:
		return "hold"
	}
}
