package provisioner

import (
	"context"

	"github.com/docker/docker/api/types/container"
	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

// stop politely so cowrie flushes before anything is copied
func (p *Provisioner) Drain(ctx context.Context, hp *apiary.Honeypot) error {
	hp.State = apiary.Draining
	t := int(p.drainTimeout.Seconds())
	return p.cli.ContainerStop(ctx, hp.ID, container.StopOptions{Timeout: &t})
}
