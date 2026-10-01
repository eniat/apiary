// Package metrics gathers the scaling signal
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Usage struct {
	ID       string
	CPUPct   float64
	MemBytes uint64
	Valid    bool // false until a second sample gives a delta
}

type prev struct {
	cpu    uint64
	system uint64
}

type Resources struct {
	cli  *client.Client
	mu   sync.Mutex
	last map[string]prev
}

func NewResources(cli *client.Client) *Resources {
	return &Resources{cli: cli, last: map[string]prev{}}
}

// one shot per id, streaming holds a connection open per container
func (r *Resources) Sample(ctx context.Context, ids []string) ([]Usage, error) {
	out := make([]Usage, len(ids))
	errs := make([]error, len(ids))

	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := r.one(ctx, id)
			out[i], errs[i] = u, err
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			return out, fmt.Errorf("%s: %w", ids[i], err)
		}
	}
	return out, nil
}

func (r *Resources) one(ctx context.Context, id string) (Usage, error) {
	resp, err := r.cli.ContainerStatsOneShot(ctx, id)
	if err != nil {
		return Usage{ID: id}, err
	}
	defer resp.Body.Close()

	var s container.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return Usage{ID: id}, err
	}

	u := Usage{ID: id, MemBytes: memUsage(s)}
	cpu := s.CPUStats.CPUUsage.TotalUsage
	sys := s.CPUStats.SystemUsage

	r.mu.Lock()
	p, seen := r.last[id]
	r.last[id] = prev{cpu: cpu, system: sys}
	r.mu.Unlock()

	if seen {
		u.CPUPct, u.Valid = cpuPct(p.cpu, cpu, p.system, sys, onlineCPUs(s))
	}
	return u, nil
}

// the raw counters only climb so a rate needs both deltas
func cpuPct(cpu0, cpu1, sys0, sys1 uint64, cpus uint32) (float64, bool) {
	if cpu1 < cpu0 || sys1 <= sys0 || cpus == 0 {
		return 0, false
	}
	return float64(cpu1-cpu0) / float64(sys1-sys0) * float64(cpus) * 100, true
}

// file is page cache
func memUsage(s container.StatsResponse) uint64 {
	used := s.MemoryStats.Usage
	if c, ok := s.MemoryStats.Stats["file"]; ok && c < used {
		return used - c
	}
	return used
}

func onlineCPUs(s container.StatsResponse) uint32 {
	if s.CPUStats.OnlineCPUs > 0 {
		return s.CPUStats.OnlineCPUs
	}
	return uint32(len(s.CPUStats.CPUUsage.PercpuUsage))
}
