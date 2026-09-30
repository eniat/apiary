// Package policy decides scaling. Standard library only.
package policy

import "time"

type Action int

const (
	Hold Action = iota
	ScaleUp
	ScaleDown
)

// Snapshot is one immutable reading. Now is passed in so no decision reads the clock.
type Snapshot struct {
	Now          time.Time
	Live         int
	Warm         int
	Sessions     int
	Unserved     int
	LastAction   time.Time
	LastDuration time.Duration
}

type Decider interface {
	Decide(Snapshot) Action
}
