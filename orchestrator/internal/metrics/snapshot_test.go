package metrics

import (
	"testing"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/policy"
)

func hp(id string, st apiary.State) *apiary.Honeypot {
	return &apiary.Honeypot{ID: id, State: st}
}

func TestAggregate(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	last := now.Add(-30 * time.Second)

	cases := []struct {
		name     string
		hps      []*apiary.Honeypot
		us       []Usage
		cs       []Count
		unserved uint64
		want     policy.Snapshot
	}{
		{
			name: "nothing running",
			want: policy.Snapshot{Now: now, LastAction: last},
		},
		{
			name: "two live one warm one dead",
			hps:  []*apiary.Honeypot{hp("a", apiary.Live), hp("b", apiary.Live), hp("c", apiary.Warm), hp("d", apiary.Dead)},
			us:   []Usage{{ID: "a", CPUPct: 12, MemBytes: 1 << 20, Valid: true}, {ID: "b", CPUPct: 8, MemBytes: 2 << 20, Valid: true}},
			cs:   []Count{{ID: "a", Sessions: 2}, {ID: "b", Sessions: 1}},
			want: policy.Snapshot{Now: now, Live: 2, Warm: 1, Sessions: 3, CPUPct: 20, MemBytes: 3 << 20, LastAction: last},
		},
		{
			name: "first tick has no cpu delta",
			hps:  []*apiary.Honeypot{hp("a", apiary.Live)},
			us:   []Usage{{ID: "a", CPUPct: 99, MemBytes: 1 << 20}},
			cs:   []Count{{ID: "a"}},
			want: policy.Snapshot{Now: now, Live: 1, MemBytes: 1 << 20, LastAction: last},
		},
		{
			name:     "unserved with no honeypots",
			unserved: 7,
			want:     policy.Snapshot{Now: now, Unserved: 7, LastAction: last},
		},
	}

	for _, c := range cases {
		got := aggregate(now, c.hps, c.us, c.cs, c.unserved, last, 0)
		if got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestLiveIDs(t *testing.T) {
	hps := []*apiary.Honeypot{hp("a", apiary.Warm), hp("b", apiary.Live), hp("c", apiary.Draining), hp("d", apiary.Live)}
	got := liveIDs(hps)
	want := []string{"b", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
