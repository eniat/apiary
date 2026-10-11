package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/metrics"
)

// stands in for the provisioner until it exists
type fixed []*apiary.Honeypot

func (f fixed) List() []*apiary.Honeypot { return f }

func main() {
	pin := flag.String("pin", metrics.UnservedPin, "pinned unserved map")
	ticks := flag.Int("ticks", 10, "samples to take")
	flag.Parse()

	names := flag.Args()
	if len(names) == 0 {
		log.Fatal("usage: snapshot [-pin p] [-ticks n] <container>...")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	u, err := metrics.OpenUnserved(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer u.Close()

	var pool fixed
	for _, n := range names {
		pool = append(pool, &apiary.Honeypot{ID: n, State: apiary.Live})
	}

	c := metrics.NewCollector(pool, metrics.NewResources(cli), metrics.NewSessions(cli, 5*time.Minute), u)
	for range *ticks {
		now := time.Now()
		s, _, err := c.Sample(context.Background(), now, time.Time{}, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s live %d warm %d sessions %d unserved %d cpu %.1f%% mem %d MiB\n",
			now.Format("15:04:05"), s.Live, s.Warm, s.Sessions, s.Unserved, s.CPUPct, s.MemBytes>>20)
		time.Sleep(2 * time.Second)
	}
}
