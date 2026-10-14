// Package loop ties metrics policy and the actors into one tick.
package loop

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	Took     time.Duration
	Refilled int
	Reaped   int
	Note     string
}

type Loop struct {
	coll  Collector
	pol   policy.Decider
	pool  Pool
	reap  Reaper
	warm  int
	alert func(error)

	wg sync.WaitGroup
	mu sync.Mutex
	// creates already asked for and not yet finished
	inflight int

	lastAction time.Time
	lastDur    time.Duration
}

func New(c Collector, p policy.Decider, pool Pool, r Reaper, warm int, alert func(error)) *Loop {
	if alert == nil {
		alert = func(error) {}
	}
	return &Loop{coll: c, pol: p, pool: pool, reap: r, warm: warm, alert: alert}
}

// waits for refills still running. call before shutting down
func (l *Loop) Drain() { l.wg.Wait() }

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
		err = l.up(&res)
	case policy.ScaleDown:
		res.Reaped, err = l.reap.ReapIdle(ctx, now, counts)
	}
	if err != nil {
		return res, err
	}

	// every tick. the pool is a target not a reaction to a scale up
	res.Refilled = l.refill(ctx)

	// a hold costs nothing so it is not an action
	if res.Action != policy.Hold {
		l.lastAction = now
		l.lastDur = time.Since(start)
	}
	return res, nil
}

// a map write. the container was started minutes ago
func (l *Loop) up(res *Result) error {
	start := time.Now()
	hp, err := l.pool.Promote(context.Background())
	res.Took = time.Since(start)

	switch {
	case errors.Is(err, provisioner.ErrPoolEmpty):
		res.Note = "warm pool empty"
		return nil
	case err != nil:
		return err
	}
	res.Promoted = hp.ID
	return nil
}

// fires and returns. a create takes seconds and the tick cant wait for it
func (l *Loop) refill(ctx context.Context) int {
	l.mu.Lock()
	short := l.warm - warmCount(l.pool.List()) - l.inflight
	if short <= 0 {
		l.mu.Unlock()
		return 0
	}
	l.inflight += short
	l.mu.Unlock()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		_, err := l.pool.Create(ctx, short)

		l.mu.Lock()
		l.inflight -= short
		l.mu.Unlock()

		if err != nil && ctx.Err() == nil {
			l.alert(fmt.Errorf("refill %d: %w", short, err))
		}
	}()
	return short
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
			l.Drain()
			return ctx.Err()
		case now := <-t.C:
			res, err := l.Tick(ctx, now)
			if err != nil {
				l.Drain()
				return fmt.Errorf("tick: %w", err)
			}
			report(res)
		}
	}
}
