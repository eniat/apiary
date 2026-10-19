// Package reaper archives and destroys idle honeypots.
package reaper

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

// what the reaper needs from the provisioner
type Pool interface {
	List() []*apiary.Honeypot
	Drain(context.Context, *apiary.Honeypot) error
	Discard(context.Context, *apiary.Honeypot) error
}

// what the reaper needs from the registrar
type Rows interface {
	Deregister(net.IP) error
	SourcesFor(string) []net.IP
	Bound(string, time.Time, time.Duration) bool
	Refresh(string, time.Time)
}

type Archiver interface {
	Archive(context.Context, *apiary.Honeypot) error
}

type Reaper struct {
	pool     Pool
	rows     Rows
	arch     Archiver
	grace    time.Duration
	affinity time.Duration
	alert    func(error)
}

// grace is silence before a honeypot counts as idle
// affinity is how long after that its attacker keeps it
func New(p Pool, r Rows, a Archiver, grace, affinity time.Duration, alert func(error)) *Reaper {
	if alert == nil {
		alert = func(error) {}
	}
	return &Reaper{pool: p, rows: r, arch: a, grace: grace, affinity: affinity, alert: alert}
}

var _ apiary.Reaper = (*Reaper)(nil)

func (r *Reaper) ReapIdle(ctx context.Context, now time.Time, counts map[string]int) (int, error) {
	hps := r.pool.List()
	r.touch(hps, counts, now)

	n := 0
	for _, hp := range r.idle(hps, counts, now) {
		done, err := r.teardown(ctx, hp)
		if err != nil {
			return n, err
		}
		if done {
			n++
		}
	}
	return n, nil
}

// deregister then drain then archive then destroy
// registration runs the other way round and registers last
func (r *Reaper) teardown(ctx context.Context, hp *apiary.Honeypot) (bool, error) {
	for _, src := range r.rows.SourcesFor(hp.ID) {
		if err := r.rows.Deregister(src); err != nil {
			return false, fmt.Errorf("%s deregister: %w", hp.ID, err)
		}
	}
	// stop first or cowrie still holds the tail of its log
	if err := r.pool.Drain(ctx, hp); err != nil {
		return false, fmt.Errorf("%s drain: %w", hp.ID, err)
	}
	// a leaked container is cheaper than lost evidence so it stays draining
	if err := r.arch.Archive(ctx, hp); err != nil {
		r.alert(fmt.Errorf("%s archive: %w", hp.ID, err))
		return false, nil
	}
	if err := r.pool.Discard(ctx, hp); err != nil {
		return false, fmt.Errorf("%s discard: %w", hp.ID, err)
	}
	return true, nil
}

// a busy honeypot is young again and so is its binding
func (r *Reaper) touch(hps []*apiary.Honeypot, counts map[string]int, now time.Time) {
	for _, hp := range hps {
		hp.Sessions = counts[hp.ID]
		if hp.Sessions > 0 {
			hp.LastSeen = now
			r.rows.Refresh(hp.ID, now)
		}
	}
}

// live, empty past the grace, and nobody still bound to it
func (r *Reaper) idle(hps []*apiary.Honeypot, counts map[string]int, now time.Time) []*apiary.Honeypot {
	var out []*apiary.Honeypot
	for _, hp := range hps {
		if hp.State != apiary.Live {
			continue
		}
		if counts[hp.ID] > 0 {
			continue
		}
		// no last seen means nothing has set it so leave it alone
		if hp.LastSeen.IsZero() {
			continue
		}
		if now.Sub(hp.LastSeen) <= r.grace {
			continue
		}
		// the engagement outlives the session
		if r.rows.Bound(hp.ID, now, r.affinity) {
			continue
		}
		out = append(out, hp)
	}
	return out
}
