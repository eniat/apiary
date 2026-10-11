package loop

import (
	"context"
	"testing"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/policy"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fixedPolicy policy.Action

func (f fixedPolicy) Decide(policy.Snapshot) policy.Action { return policy.Action(f) }

type fakeColl struct {
	counts     map[string]int
	lastAction time.Time
	lastDur    time.Duration
}

func (f *fakeColl) Sample(_ context.Context, n, la time.Time, ld time.Duration) (policy.Snapshot, map[string]int, error) {
	f.lastAction, f.lastDur = la, ld
	return policy.Snapshot{Now: n, LastAction: la, LastDuration: ld}, f.counts, nil
}

type fakePool struct {
	hps     []*apiary.Honeypot
	empty   bool
	created int
}

func (f *fakePool) List() []*apiary.Honeypot { return f.hps }

func (f *fakePool) Promote(context.Context) (*apiary.Honeypot, error) {
	if f.empty {
		return nil, provisioner.ErrPoolEmpty
	}
	for _, hp := range f.hps {
		if hp.State == apiary.Warm {
			hp.State = apiary.Live
			return hp, nil
		}
	}
	return nil, provisioner.ErrPoolEmpty
}

func (f *fakePool) Create(_ context.Context, n int) ([]*apiary.Honeypot, error) {
	out := make([]*apiary.Honeypot, n)
	for i := range n {
		hp := &apiary.Honeypot{ID: "new", State: apiary.Warm}
		f.hps = append(f.hps, hp)
		out[i] = hp
	}
	f.created += n
	return out, nil
}

type fakeReaper struct{ calls int }

func (f *fakeReaper) ReapIdle(context.Context, time.Time, map[string]int) (int, error) {
	f.calls++
	return 1, nil
}

func warm(n int) []*apiary.Honeypot {
	out := make([]*apiary.Honeypot, n)
	for i := range n {
		out[i] = &apiary.Honeypot{ID: string(rune('a' + i)), State: apiary.Warm}
	}
	return out
}

func TestHoldDoesNothing(t *testing.T) {
	pool := &fakePool{hps: warm(2)}
	rp := &fakeReaper{}
	l := New(&fakeColl{}, fixedPolicy(policy.Hold), pool, rp, 2)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted != "" || res.Reaped != 0 || pool.created != 0 || rp.calls != 0 {
		t.Errorf("got %+v created %d reaps %d, want nothing", res, pool.created, rp.calls)
	}
}

func TestScaleUpPromotesAndRefills(t *testing.T) {
	pool := &fakePool{hps: warm(2)}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 2)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted != "a" {
		t.Errorf("got promoted %q, want a", res.Promoted)
	}
	// one warm left so one is created to reach the floor
	if res.Refilled != 1 || pool.created != 1 {
		t.Errorf("got refilled %d created %d, want 1 1", res.Refilled, pool.created)
	}
}

func TestScaleUpAtTheFloorDoesNotRefill(t *testing.T) {
	pool := &fakePool{hps: warm(3)}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 2)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Refilled != 0 || pool.created != 0 {
		t.Errorf("got refilled %d created %d, want 0 0", res.Refilled, pool.created)
	}
}

func TestScaleUpToleratesEmptyPool(t *testing.T) {
	pool := &fakePool{empty: true}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 2)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if res.Note == "" {
		t.Error("want a note about the empty pool")
	}
	if pool.created != 2 {
		t.Errorf("got created %d, want 2", pool.created)
	}
}

func TestScaleDownReaps(t *testing.T) {
	rp := &fakeReaper{}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleDown), &fakePool{}, rp, 2)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rp.calls != 1 || res.Reaped != 1 {
		t.Errorf("got %d calls reaped %d, want 1 1", rp.calls, res.Reaped)
	}
}

func TestLastActionFedBack(t *testing.T) {
	coll := &fakeColl{}
	l := New(coll, fixedPolicy(policy.ScaleDown), &fakePool{}, &fakeReaper{}, 2)

	if _, err := l.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if !coll.lastAction.IsZero() {
		t.Errorf("first tick saw %v, want zero", coll.lastAction)
	}
	if _, err := l.Tick(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !coll.lastAction.Equal(now) {
		t.Errorf("second tick saw %v, want %v", coll.lastAction, now)
	}
}

func TestHoldDoesNotAdvanceLastAction(t *testing.T) {
	coll := &fakeColl{}
	l := New(coll, fixedPolicy(policy.Hold), &fakePool{}, &fakeReaper{}, 2)

	for i := range 3 {
		if _, err := l.Tick(context.Background(), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if !coll.lastAction.IsZero() {
		t.Errorf("got %v, want zero", coll.lastAction)
	}
}
