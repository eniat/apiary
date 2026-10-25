package metrics

import (
	"context"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/policy"
)

// what the collector needs from the provisioner
type Pool interface {
	List() []*apiary.Honeypot
}

type resourceSource interface {
	Sample(context.Context, []string) ([]Usage, error)
}

type sessionSource interface {
	Sample(context.Context, []string, time.Time) ([]Count, error)
}

type unservedSource interface {
	Sample() (uint64, error)
}

type Collector struct {
	pool     Pool
	res      resourceSource
	sess     sessionSource
	unserved unservedSource
}

func NewCollector(p Pool, r resourceSource, s sessionSource, u unservedSource) *Collector {
	return &Collector{pool: p, res: r, sess: s, unserved: u}
}

// built once per tick. the snapshot goes to the policy and the counts to the reaper
func (c *Collector) Sample(ctx context.Context, now, lastAction time.Time, lastDur time.Duration) (policy.Snapshot, map[string]int, error) {
	hps := c.pool.List()
	ids := liveIDs(hps)

	us, err := c.res.Sample(ctx, ids)
	if err != nil {
		return policy.Snapshot{}, nil, err
	}
	cs, err := c.sess.Sample(ctx, ids, now)
	if err != nil {
		return policy.Snapshot{}, nil, err
	}
	un, err := c.unserved.Sample()
	if err != nil {
		return policy.Snapshot{}, nil, err
	}

	counts := make(map[string]int, len(cs))
	for _, x := range cs {
		counts[x.ID] = x.Sessions
	}
	return aggregate(now, hps, us, cs, un, lastAction, lastDur), counts, nil
}

// warm honeypots serve nothing so they are not sampled
func liveIDs(hps []*apiary.Honeypot) []string {
	var ids []string
	for _, h := range hps {
		if h.State == apiary.Live {
			ids = append(ids, h.ID)
		}
	}
	return ids
}

// pure. no docker and no kernel
func aggregate(now time.Time, hps []*apiary.Honeypot, us []Usage, cs []Count, unserved uint64, lastAction time.Time, lastDur time.Duration) policy.Snapshot {
	s := policy.Snapshot{
		Now:          now,
		Unserved:     int(unserved),
		LastAction:   lastAction,
		LastDuration: lastDur,
	}
	for _, h := range hps {
		switch h.State {
		case apiary.Live:
			s.Live++
		case apiary.Warm:
			s.Warm++
		}
	}
	// cpu is invalid until a second sample gives a delta
	for _, u := range us {
		if u.Valid {
			s.CPUPct += u.CPUPct
		}
		s.MemBytes += u.MemBytes
	}
	for _, c := range cs {
		s.Sessions += c.Sessions
	}
	return s
}
