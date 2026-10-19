package reaper

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func hp(id string, st apiary.State, age time.Duration) *apiary.Honeypot {
	return &apiary.Honeypot{ID: id, State: st, LastSeen: now.Add(-age)}
}

type fakePool struct {
	hps      []*apiary.Honeypot
	steps    []string
	discards []string
}

func (f *fakePool) List() []*apiary.Honeypot { return f.hps }

func (f *fakePool) Drain(_ context.Context, h *apiary.Honeypot) error {
	f.steps = append(f.steps, "drain "+h.ID)
	h.State = apiary.Draining
	return nil
}

func (f *fakePool) Discard(_ context.Context, h *apiary.Honeypot) error {
	f.steps = append(f.steps, "discard "+h.ID)
	f.discards = append(f.discards, h.ID)
	h.State = apiary.Dead
	return nil
}

type fakeRows struct {
	srcs      map[string][]net.IP
	bound     map[string]bool
	refreshed []string
	steps     *[]string
}

func (f *fakeRows) SourcesFor(id string) []net.IP { return f.srcs[id] }

func (f *fakeRows) Deregister(ip net.IP) error {
	if f.steps != nil {
		*f.steps = append(*f.steps, "deregister "+ip.String())
	}
	return nil
}

func (f *fakeRows) Bound(id string, _ time.Time, _ time.Duration) bool { return f.bound[id] }

func (f *fakeRows) Refresh(id string, _ time.Time) {
	f.refreshed = append(f.refreshed, id)
}

type fakeArchiver struct {
	steps *[]string
	err   error
}

func (f *fakeArchiver) Archive(_ context.Context, h *apiary.Honeypot) error {
	if f.err != nil {
		return f.err
	}
	if f.steps != nil {
		*f.steps = append(*f.steps, "archive "+h.ID)
	}
	return nil
}

func build(pool *fakePool, bound map[string]bool, srcs map[string][]net.IP, archErr error, alert func(error)) *Reaper {
	if srcs == nil {
		srcs = map[string][]net.IP{}
	}
	rows := &fakeRows{srcs: srcs, bound: bound, steps: &pool.steps}
	arch := &fakeArchiver{steps: &pool.steps, err: archErr}
	return New(pool, rows, arch, time.Minute, 5*time.Minute, alert)
}

func TestIdle(t *testing.T) {
	cases := []struct {
		name   string
		hps    []*apiary.Honeypot
		counts map[string]int
		bound  map[string]bool
		want   int
	}{
		{"live and long idle", []*apiary.Honeypot{hp("a", apiary.Live, 5*time.Minute)}, nil, nil, 1},
		{"live and recently idle", []*apiary.Honeypot{hp("a", apiary.Live, time.Second)}, nil, nil, 0},
		{"idle exactly at the grace", []*apiary.Honeypot{hp("a", apiary.Live, time.Minute)}, nil, nil, 0},
		{"holding a session", []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}, map[string]int{"a": 1}, nil, 0},
		{"still bound", []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}, nil, map[string]bool{"a": true}, 0},
		{"binding expired", []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}, nil, map[string]bool{"a": false}, 1},
		{"warm is never reaped", []*apiary.Honeypot{hp("a", apiary.Warm, time.Hour)}, nil, nil, 0},
		{"draining is never retried", []*apiary.Honeypot{hp("a", apiary.Draining, time.Hour)}, nil, nil, 0},
		{"no last seen", []*apiary.Honeypot{{ID: "a", State: apiary.Live}}, nil, nil, 0},
		{"bound one spared the other taken", []*apiary.Honeypot{
			hp("a", apiary.Live, time.Hour),
			hp("b", apiary.Live, time.Hour),
		}, nil, map[string]bool{"b": true}, 1},
	}

	for _, c := range cases {
		pool := &fakePool{hps: c.hps}
		r := build(pool, c.bound, nil, nil, nil)
		if got := len(r.idle(c.hps, c.counts, now)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestTouchRefreshesBusy(t *testing.T) {
	h := hp("a", apiary.Live, time.Hour)
	pool := &fakePool{hps: []*apiary.Honeypot{h}}
	rows := &fakeRows{srcs: map[string][]net.IP{}, steps: &pool.steps}
	r := New(pool, rows, &fakeArchiver{}, time.Minute, 5*time.Minute, nil)

	r.touch(pool.hps, map[string]int{"a": 2}, now)
	if !h.LastSeen.Equal(now) {
		t.Errorf("got %v, want %v", h.LastSeen, now)
	}
	if h.Sessions != 2 {
		t.Errorf("got %d sessions, want 2", h.Sessions)
	}
	if len(rows.refreshed) != 1 || rows.refreshed[0] != "a" {
		t.Errorf("got %v refreshed, want [a]", rows.refreshed)
	}
}

func TestTouchLeavesIdleBindingsAlone(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}}
	rows := &fakeRows{srcs: map[string][]net.IP{}, steps: &pool.steps}
	r := New(pool, rows, &fakeArchiver{}, time.Minute, 5*time.Minute, nil)

	r.touch(pool.hps, nil, now)
	if len(rows.refreshed) != 0 {
		t.Errorf("got %v refreshed, want none", rows.refreshed)
	}
}

func TestTeardownOrder(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}}
	r := build(pool, nil, map[string][]net.IP{"a": {net.ParseIP("10.10.10.20")}}, nil, nil)

	n, err := r.ReapIdle(context.Background(), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("got %d reaped, want 1", n)
	}

	want := []string{"deregister 10.10.10.20", "drain a", "archive a", "discard a"}
	if len(pool.steps) != len(want) {
		t.Fatalf("got %v, want %v", pool.steps, want)
	}
	for i := range want {
		if pool.steps[i] != want[i] {
			t.Errorf("step %d: got %q, want %q", i, pool.steps[i], want[i])
		}
	}
}

func TestArchiveFailureKeepsTheContainer(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}}
	var alerted error
	r := build(pool, nil, nil, errors.New("disk full"), func(err error) { alerted = err })

	n, err := r.ReapIdle(context.Background(), now, nil)
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if n != 0 {
		t.Errorf("got %d reaped, want 0", n)
	}
	if len(pool.discards) != 0 {
		t.Errorf("got %v destroyed, want none", pool.discards)
	}
	if pool.hps[0].State != apiary.Draining {
		t.Errorf("got state %v, want Draining", pool.hps[0].State)
	}
	if alerted == nil {
		t.Error("want an alert, got none")
	}
}

func TestReapSparesBoundOne(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{
		hp("a", apiary.Live, time.Hour),
		hp("b", apiary.Live, time.Hour),
	}}
	r := build(pool, map[string]bool{"b": true}, nil, nil, nil)

	n, err := r.ReapIdle(context.Background(), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(pool.discards) != 1 || pool.discards[0] != "a" {
		t.Errorf("got %d reaped %v, want 1 [a]", n, pool.discards)
	}
}
