package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/loop"
	"github.com/eniat/apiary/orchestrator/internal/metrics"
	"github.com/eniat/apiary/orchestrator/internal/policy"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
	"github.com/eniat/apiary/orchestrator/internal/reaper"
	"github.com/eniat/apiary/orchestrator/internal/registrar"
)

func main() {
	warm := flag.Int("warm", 2, "warm pool floor")
	up := flag.Int("up", 2, "unserved flows that trigger a scale up")
	minLive := flag.Int("min-live", 1, "live floor the policy respects")
	grace := flag.Duration("grace", 60*time.Second, "idle time before a honeypot is destroyed")
	every := flag.Duration("every", 5*time.Second, "tick interval")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	pin := flag.String("pin", registrar.RedirectPin, "pinned redirect map")
	upin := flag.String("unserved-pin", metrics.UnservedPin, "pinned unserved map")
	archive := flag.String("archive", "/var/lib/apiary/archive", "durable log archive root")
	ticks := flag.Int("ticks", 0, "stop after n ticks, zero runs until ctrl-c")
	flag.Parse()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	// cancelled on ctrl-c so the loop unwinds instead of dying mid action
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	p := provisioner.New(cli, "cowrie/cowrie:latest", "apiary-net", *logs)
	if _, err := p.Create(ctx, *warm+1); err != nil {
		log.Fatal(err)
	}
	if _, err := p.Promote(ctx); err != nil {
		log.Fatal(err)
	}

	reg, err := registrar.Open(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer reg.Close()

	un, err := metrics.OpenUnserved(*upin)
	if err != nil {
		log.Fatal(err)
	}
	defer un.Close()

	coll := metrics.NewCollector(p, metrics.NewResources(cli), metrics.NewSessions(cli, 5*time.Minute), un)
	rp := reaper.New(p, reg, reaper.DirArchiver{LogRoot: *logs, Dest: *archive}, *grace, func(err error) { log.Print(err) })
	l := loop.New(coll, policy.Threshold{Up: *up, MinLive: *minLive}, p, rp, *warm, func(err error) { log.Print(err) })

	n := 0
	err = l.Run(ctx, *every, func(res loop.Result) {
		s := res.Snapshot
		fmt.Printf("%s live %d warm %d sessions %d unserved %d action %s promoted %q refilled %d reaped %d %s\n",
			s.Now.Format("15:04:05"), s.Live, s.Warm, s.Sessions, s.Unserved,
			res.Action, res.Promoted, res.Refilled, res.Reaped, res.Note)
		n++
		if *ticks > 0 && n >= *ticks {
			stop()
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}

	for _, hp := range p.List() {
		if err := p.Discard(context.Background(), hp); err != nil {
			log.Print(err)
		}
	}
	fmt.Println("torn down")
}
