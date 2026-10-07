// Package apiary holds the orchestrator component contracts.
package apiary

import (
	"context"
	"net"
	"time"
)

// where cowrie writes its json log inside the image
const CowrieLogDir = "/cowrie/cowrie-git/var/log/cowrie"

type State int

const (
	Creating State = iota
	Warm
	Live
	Draining
	Dead
)

// Honeypot is what the registrar and reaper need. Not everything docker knows.
type Honeypot struct {
	ID       string
	IP       net.IP
	MAC      net.HardwareAddr
	Ifindex  uint32
	State    State
	Sessions int
	LastSeen time.Time
}

type Provisioner interface {
	Promote(context.Context) (*Honeypot, error)
	Discard(context.Context, *Honeypot) error
	List() []*Honeypot
}

type Registrar interface {
	Register(*Honeypot) error
	Deregister(*Honeypot) error
}

type Reaper interface {
	ReapIdle(context.Context) (int, error)
}

type Metrics interface {
	Sample(time.Time) (sessions int, unserved int, err error)
}
