package provisioner

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errRefused = errors.New("connection refused")

// answers only after n failures
func flaky(n int) (dialer, *int) {
	calls := 0
	return func(ctx context.Context, addr string) error {
		calls++
		if calls <= n {
			return errRefused
		}
		return nil
	}, &calls
}

func TestWaitReadyRetries(t *testing.T) {
	dial, calls := flaky(3)
	if _, err := waitReady(context.Background(), dial, "1.2.3.4:2222", time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if *calls != 4 {
		t.Errorf("got %d calls, want 4", *calls)
	}
}

func TestWaitReadyFirstTry(t *testing.T) {
	dial, calls := flaky(0)
	if _, err := waitReady(context.Background(), dial, "1.2.3.4:2222", time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Errorf("got %d calls, want 1", *calls)
	}
}

func TestWaitReadyTimesOut(t *testing.T) {
	dial := func(ctx context.Context, addr string) error { return errRefused }
	if _, err := waitReady(context.Background(), dial, "1.2.3.4:2222", 20*time.Millisecond, time.Millisecond); err == nil {
		t.Error("want a timeout, got nil")
	}
}

func TestWaitReadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dial := func(ctx context.Context, addr string) error { return errRefused }
	_, err := waitReady(ctx, dial, "1.2.3.4:2222", time.Minute, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}
