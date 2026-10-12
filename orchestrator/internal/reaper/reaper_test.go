package reaper

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func hp(id string, st apiary.State, age time.Duration) *apiary.Honeypot {
	return &apiary.Honeypot{ID: id, State: st, LastSeen: now.Add(-age)}
}

func TestIdle(t *testing.T) {
	grace := time.Minute

	cases := []struct {
		name   string
		hps    []*apiary.Honeypot
		counts map[string]int
		want   int
	}{
		{"live and long idle", []*apiary.Honeypot{hp("a", apiary.Live, 5*time.Minute)}, nil, 1},
		{"live and recently idle", []*apiary.Honeypot{hp("a", apiary.Live, time.Second)}, nil, 0},
		{"idle exactly at the grace", []*apiary.Honeypot{hp("a", apiary.Live, time.Minute)}, nil, 0},
		{"holding a session", []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}, map[string]int{"a": 1}, 0},
		{"warm is never reaped", []*apiary.Honeypot{hp("a", apiary.Warm, time.Hour)}, nil, 0},
		{"draining is never retried", []*apiary.Honeypot{hp("a", apiary.Draining, time.Hour)}, nil, 0},
		{"no last seen", []*apiary.Honeypot{{ID: "a", State: apiary.Live}}, nil, 0},
		{"one of three", []*apiary.Honeypot{
			hp("a", apiary.Live, time.Hour),
			hp("b", apiary.Live, time.Second),
			hp("c", apiary.Live, time.Hour),
		}, map[string]int{"c": 2}, 1},
	}

	for _, c := range cases {
		if got := len(idle(c.hps, c.counts, now, grace)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestTouchRefreshesBusy(t *testing.T) {
	h := hp("a", apiary.Live, time.Hour)
	touch([]*apiary.Honeypot{h}, map[string]int{"a": 2}, now)
	if !h.LastSeen.Equal(now) {
		t.Errorf("got %v, want %v", h.LastSeen, now)
	}
	if h.Sessions != 2 {
		t.Errorf("got %d sessions, want 2", h.Sessions)
	}
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
	srcs  map[string][]net.IP
	steps *[]string
}

func (f *fakeRows) SourcesFor(id string) []net.IP { return f.srcs[id] }

func (f *fakeRows) Deregister(ip net.IP) error {
	*f.steps = append(*f.steps, "deregister "+ip.String())
	return nil
}

type fakeArchiver struct {
	steps *[]string
	err   error
}

func (f *fakeArchiver) Archive(_ context.Context, h *apiary.Honeypot) error {
	if f.err != nil {
		return f.err
	}
	*f.steps = append(*f.steps, "archive "+h.ID)
	return nil
}

func TestTeardownOrder(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{hp("a", apiary.Live, time.Hour)}}
	rows := &fakeRows{srcs: map[string][]net.IP{"a": {net.ParseIP("10.10.10.20")}}, steps: &pool.steps}
	arch := &fakeArchiver{steps: &pool.steps}

	r := New(pool, rows, arch, time.Minute, nil)
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
	rows := &fakeRows{srcs: map[string][]net.IP{}, steps: &pool.steps}
	arch := &fakeArchiver{steps: &pool.steps, err: errors.New("disk full")}

	var alerted error
	r := New(pool, rows, arch, time.Minute, func(err error) { alerted = err })

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

func TestReapSparesBusyOne(t *testing.T) {
	pool := &fakePool{hps: []*apiary.Honeypot{
		hp("a", apiary.Live, time.Hour),
		hp("b", apiary.Live, time.Hour),
	}}
	rows := &fakeRows{srcs: map[string][]net.IP{}, steps: &pool.steps}
	arch := &fakeArchiver{steps: &pool.steps}

	r := New(pool, rows, arch, time.Minute, nil)
	n, err := r.ReapIdle(context.Background(), now, map[string]int{"b": 1})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(pool.discards) != 1 || pool.discards[0] != "a" {
		t.Errorf("got %d reaped %v, want 1 [a]", n, pool.discards)
	}
}
