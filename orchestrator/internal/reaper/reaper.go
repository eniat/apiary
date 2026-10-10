// Package reaper destroys idle honeypots.
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
	Discard(context.Context, *apiary.Honeypot) error
}

// what the reaper needs from the registrar
type Rows interface {
	Deregister(net.IP) error
	SourcesFor(string) []net.IP
}

type Reaper struct {
	pool  Pool
	rows  Rows
	grace time.Duration
}

func New(p Pool, r Rows, grace time.Duration) *Reaper {
	return &Reaper{pool: p, rows: r, grace: grace}
}

var _ apiary.Reaper = (*Reaper)(nil)

// rows go first or they point at a dead container
func (r *Reaper) ReapIdle(ctx context.Context, now time.Time, counts map[string]int) (int, error) {
	hps := r.pool.List()
	touch(hps, counts, now)

	n := 0
	for _, hp := range idle(hps, counts, now, r.grace) {
		for _, src := range r.rows.SourcesFor(hp.ID) {
			if err := r.rows.Deregister(src); err != nil {
				return n, fmt.Errorf("%s: %w", hp.ID, err)
			}
		}
		// logs stay under the log root so destroying loses nothing
		if err := r.pool.Discard(ctx, hp); err != nil {
			return n, fmt.Errorf("%s: %w", hp.ID, err)
		}
		n++
	}
	return n, nil
}

// a busy honeypot is young again
func touch(hps []*apiary.Honeypot, counts map[string]int, now time.Time) {
	for _, hp := range hps {
		hp.Sessions = counts[hp.ID]
		if hp.Sessions > 0 {
			hp.LastSeen = now
		}
	}
}

// pure. live and empty for longer than the grace
func idle(hps []*apiary.Honeypot, counts map[string]int, now time.Time, grace time.Duration) []*apiary.Honeypot {
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
		if now.Sub(hp.LastSeen) <= grace {
			continue
		}
		out = append(out, hp)
	}
	return out
}
