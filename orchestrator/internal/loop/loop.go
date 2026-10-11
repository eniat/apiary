// Package loop ties metrics policy and the actors into one tick.
package loop

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/policy"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
)

type Collector interface {
	Sample(context.Context, time.Time, time.Time, time.Duration) (policy.Snapshot, map[string]int, error)
}

type Pool interface {
	Create(context.Context, int) ([]*apiary.Honeypot, error)
	Promote(context.Context) (*apiary.Honeypot, error)
	List() []*apiary.Honeypot
}

type Reaper interface {
	ReapIdle(context.Context, time.Time, map[string]int) (int, error)
}

// what one tick did
type Result struct {
	Snapshot policy.Snapshot
	Action   policy.Action
	Promoted string
	Refilled int
	Reaped   int
	Note     string
}

type Loop struct {
	coll Collector
	pol  policy.Decider
	pool Pool
	reap Reaper
	warm int

	lastAction time.Time
	lastDur    time.Duration
}

func New(c Collector, p policy.Decider, pool Pool, r Reaper, warm int) *Loop {
	return &Loop{coll: c, pol: p, pool: pool, reap: r, warm: warm}
}

// now is passed in so nothing below here reads the clock to decide
func (l *Loop) Tick(ctx context.Context, now time.Time) (Result, error) {
	snap, counts, err := l.coll.Sample(ctx, now, l.lastAction, l.lastDur)
	if err != nil {
		return Result{}, err
	}

	res := Result{Snapshot: snap, Action: l.pol.Decide(snap)}
	start := time.Now()

	switch res.Action {
	case policy.ScaleUp:
		err = l.up(ctx, &res)
	case policy.ScaleDown:
		res.Reaped, err = l.reap.ReapIdle(ctx, now, counts)
	}
	if err != nil {
		return res, err
	}

	// a hold costs nothing so it is not an action
	if res.Action != policy.Hold {
		l.lastAction = now
		l.lastDur = time.Since(start)
	}
	return res, nil
}

// promote then refill. a dry pool is tolerated
func (l *Loop) up(ctx context.Context, res *Result) error {
	hp, err := l.pool.Promote(ctx)
	switch {
	case errors.Is(err, provisioner.ErrPoolEmpty):
		res.Note = "warm pool empty"
	case err != nil:
		return err
	default:
		res.Promoted = hp.ID
	}

	short := l.warm - warmCount(l.pool.List())
	if short <= 0 {
		return nil
	}
	hps, err := l.pool.Create(ctx, short)
	if err != nil {
		return err
	}
	res.Refilled = len(hps)
	return nil
}

func warmCount(hps []*apiary.Honeypot) int {
	n := 0
	for _, hp := range hps {
		if hp.State == apiary.Warm {
			n++
		}
	}
	return n
}

// ticks until the context is done
func (l *Loop) Run(ctx context.Context, every time.Duration, report func(Result)) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-t.C:
			res, err := l.Tick(ctx, now)
			if err != nil {
				return fmt.Errorf("tick: %w", err)
			}
			report(res)
		}
	}
}
