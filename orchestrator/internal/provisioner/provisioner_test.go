package provisioner

import (
	"context"
	"errors"
	"testing"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

func fixture(states ...apiary.State) *Provisioner {
	p := &Provisioner{pots: map[string]*apiary.Honeypot{}}
	for i, st := range states {
		id := string(rune('a' + i))
		p.pots[id] = &apiary.Honeypot{ID: id, State: st}
	}
	return p
}

func TestPromoteTakesWarm(t *testing.T) {
	p := fixture(apiary.Live, apiary.Warm)

	hp, err := p.Promote(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hp.State != apiary.Live {
		t.Errorf("got state %v, want Live", hp.State)
	}

	if _, err := p.Promote(context.Background()); !errors.Is(err, ErrPoolEmpty) {
		t.Errorf("got %v, want ErrPoolEmpty", err)
	}
}

func TestPromoteEmptyPool(t *testing.T) {
	p := fixture()
	if _, err := p.Promote(context.Background()); !errors.Is(err, ErrPoolEmpty) {
		t.Errorf("got %v, want ErrPoolEmpty", err)
	}
}

func TestListCounts(t *testing.T) {
	p := fixture(apiary.Warm, apiary.Live, apiary.Creating)
	if got := len(p.List()); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}
