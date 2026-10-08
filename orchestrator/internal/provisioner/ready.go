package provisioner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// cowrie listens here inside the container
const potPort = 2222

type dialer func(ctx context.Context, addr string) error

func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// retries until the port answers or the deadline passes
func waitReady(ctx context.Context, dial dialer, addr string, timeout, backoff time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)

	for {
		attempt, cancel := context.WithTimeout(ctx, backoff*5)
		err := dial(attempt, addr)
		cancel()
		if err == nil {
			return time.Since(start), nil
		}
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("%s not ready in %s: %w", addr, timeout, err)
		}
		time.Sleep(backoff)
	}
}
