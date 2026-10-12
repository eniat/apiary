// Package apiary holds the orchestrator component contracts.
package apiary

import (
	"context"
	"net"
	"time"
)

// where cowrie writes its json log inside the image
const CowrieLogDir = "/cowrie/cowrie-git/var/log/cowrie"

// tty recordings and host keys live here
const CowrieStateDir = "/cowrie/cowrie-git/var/lib/cowrie"

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
	Register(net.IP, *Honeypot) error
	Deregister(net.IP) error
}

type Reaper interface {
	ReapIdle(context.Context, time.Time, map[string]int) (int, error)
}

type Metrics interface {
	Sample(time.Time) (sessions int, unserved int, err error)
}
