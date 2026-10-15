package loop

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/policy"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

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

// create is slow on purpose so a blocking refill would show up as a failing deadline
type fakePool struct {
	mu      sync.Mutex
	hps     []*apiary.Honeypot
	empty   bool
	created int
	delay   time.Duration
}

func (f *fakePool) List() []*apiary.Honeypot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*apiary.Honeypot, len(f.hps))
	copy(out, f.hps)
	return out
}

func (f *fakePool) Promote(context.Context) (*apiary.Honeypot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*apiary.Honeypot, n)
	for i := range n {
		hp := &apiary.Honeypot{ID: "new", State: apiary.Warm}
		f.hps = append(f.hps, hp)
		out[i] = hp
	}
	f.created += n
	return out, nil
}

func (f *fakePool) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created
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

func TestHoldPromotesNothing(t *testing.T) {
	pool := &fakePool{hps: warm(2)}
	rp := &fakeReaper{}
	l := New(&fakeColl{}, fixedPolicy(policy.Hold), pool, rp, 2, nil)

	res, err := l.Tick(context.Background(), now)
	l.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted != "" || res.Reaped != 0 || pool.count() != 0 || rp.calls != 0 {
		t.Errorf("got %+v created %d reaps %d, want nothing", res, pool.count(), rp.calls)
	}
}

func TestScaleUpPromotesAndRefills(t *testing.T) {
	pool := &fakePool{hps: warm(2)}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 2, nil)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted != "a" {
		t.Errorf("got promoted %q, want a", res.Promoted)
	}
	// one warm left so one is created to reach the floor
	if res.Refilled != 1 {
		t.Errorf("got refilled %d, want 1", res.Refilled)
	}
	l.Drain()
	if pool.count() != 1 {
		t.Errorf("got created %d, want 1", pool.count())
	}
}

func TestRefillDoesNotBlockTheTick(t *testing.T) {
	pool := &fakePool{hps: warm(1), delay: 300 * time.Millisecond}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 3, nil)

	start := time.Now()
	if _, err := l.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	if took > 100*time.Millisecond {
		t.Errorf("tick took %s, want it to return before the create finishes", took)
	}
	l.Drain()
	if pool.count() == 0 {
		t.Error("the refill never ran")
	}
}

func TestRefillsDoNotStack(t *testing.T) {
	pool := &fakePool{delay: 200 * time.Millisecond}
	l := New(&fakeColl{}, fixedPolicy(policy.Hold), pool, &fakeReaper{}, 3, nil)

	// three ticks inside one slow create. only the first should ask for anything
	for range 3 {
		if _, err := l.Tick(context.Background(), now); err != nil {
			t.Fatal(err)
		}
	}
	l.Drain()
	if pool.count() != 3 {
		t.Errorf("got created %d, want 3", pool.count())
	}
}

func TestScaleUpToleratesEmptyPool(t *testing.T) {
	pool := &fakePool{empty: true}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 2, nil)

	res, err := l.Tick(context.Background(), now)
	l.Drain()
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if res.Note == "" {
		t.Error("want a note about the empty pool")
	}
	if pool.count() != 2 {
		t.Errorf("got created %d, want 2", pool.count())
	}
}

func TestScaleDownReaps(t *testing.T) {
	rp := &fakeReaper{}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleDown), &fakePool{}, rp, 0, nil)

	res, err := l.Tick(context.Background(), now)
	l.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if rp.calls != 1 || res.Reaped != 1 {
		t.Errorf("got %d calls reaped %d, want 1 1", rp.calls, res.Reaped)
	}
}

func TestLastActionFedBack(t *testing.T) {
	coll := &fakeColl{}
	l := New(coll, fixedPolicy(policy.ScaleDown), &fakePool{}, &fakeReaper{}, 0, nil)

	if _, err := l.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if !coll.lastAction.IsZero() {
		t.Errorf("first tick saw %v, want zero", coll.lastAction)
	}
	if _, err := l.Tick(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	l.Drain()
	if !coll.lastAction.Equal(now) {
		t.Errorf("second tick saw %v, want %v", coll.lastAction, now)
	}
}

func TestHoldDoesNotAdvanceLastAction(t *testing.T) {
	coll := &fakeColl{}
	l := New(coll, fixedPolicy(policy.Hold), &fakePool{}, &fakeReaper{}, 0, nil)

	for i := range 3 {
		if _, err := l.Tick(context.Background(), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	l.Drain()
	if !coll.lastAction.IsZero() {
		t.Errorf("got %v, want zero", coll.lastAction)
	}
}

func TestColdCreatesBeforePromoting(t *testing.T) {
	pool := &fakePool{delay: 200 * time.Millisecond}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 0, nil)
	l.Cold = true

	res, err := l.Tick(context.Background(), now)
	l.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted == "" {
		t.Error("want a promotion, got none")
	}
	if res.Took < 200*time.Millisecond {
		t.Errorf("took %s, want the create to be on the tick", res.Took)
	}
	if pool.count() != 1 {
		t.Errorf("got created %d, want 1", pool.count())
	}
}

func TestWarmPromotesWithoutCreating(t *testing.T) {
	pool := &fakePool{hps: warm(1), delay: 200 * time.Millisecond}
	l := New(&fakeColl{}, fixedPolicy(policy.ScaleUp), pool, &fakeReaper{}, 0, nil)

	res, err := l.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Promoted != "a" {
		t.Errorf("got %q, want a", res.Promoted)
	}
	if res.Took > 10*time.Millisecond {
		t.Errorf("took %s, want a map write", res.Took)
	}
	l.Drain()
}
