package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
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
	down := flag.Int("down", 0, "unserved at or below this allows a scale down")
	policyName := flag.String("policy", "hysteresis", "threshold or hysteresis")
	coolUp := flag.Duration("cooldown-up", 0, "minimum gap before another scale up")
	coolDown := flag.Duration("cooldown-down", 30*time.Second, "minimum gap before another scale down")
	grace := flag.Duration("grace", 60*time.Second, "idle time before a honeypot is destroyed")
	affinity := flag.Duration("affinity", 5*time.Minute, "how long a source keeps its honeypot after the last session")
	every := flag.Duration("every", 5*time.Second, "tick interval")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	pin := flag.String("pin", registrar.RedirectPin, "pinned redirect map")
	upin := flag.String("unserved-pin", metrics.UnservedPin, "pinned unserved map")
	archive := flag.String("archive", "/var/lib/apiary/archive", "durable log archive root")
	csvPath := flag.String("csv", "", "write one row per tick to this path")
	ticks := flag.Int("ticks", 0, "stop after n ticks, zero runs until ctrl-c")
	cold := flag.Bool("cold", false, "create on demand instead of promoting from the pool")
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
	rp := reaper.New(p, reg, reaper.DirArchiver{LogRoot: *logs, Dest: *archive}, *grace, *affinity, *minLive, func(err error) { log.Print(err) })
	var dec policy.Decider = policy.Hysteresis{Up: *up, Down: *down, MinLive: *minLive}
	if *policyName == "threshold" {
		dec = policy.Threshold{Up: *up, MinLive: *minLive}
	}

	if *coolUp > 0 || *coolDown > 0 {
		dec = policy.Cooled{Decider: dec, Up: *coolUp, Down: *coolDown}
	}

	l := loop.New(coll, dec, p, rp, *warm, func(err error) { log.Print(err) })

	var rows *csv.Writer
	if *csvPath != "" {
		f, err := os.Create(*csvPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		rows = csv.NewWriter(f)
		defer rows.Flush()
		if err := rows.Write([]string{"time", "live", "warm", "sessions", "unserved", "action", "promoted", "refilled", "reaped"}); err != nil {
			log.Fatal(err)
		}
	}

	l.Cold = *cold

	n := 0
	err = l.Run(ctx, *every, func(res loop.Result) {
		s := res.Snapshot
		fmt.Printf("%s live %d warm %d sessions %d unserved %d action %s promoted %q refilled %d reaped %d %s\n",
			s.Now.Format("15:04:05"), s.Live, s.Warm, s.Sessions, s.Unserved,
			res.Action, res.Promoted, res.Refilled, res.Reaped, res.Note)
		if res.Took > 0 {
			fmt.Printf("  scale up took %s\n", res.Took.Round(time.Microsecond))
		}
		if rows != nil {
			_ = rows.Write([]string{
				s.Now.Format(time.RFC3339), strconv.Itoa(s.Live), strconv.Itoa(s.Warm),
				strconv.Itoa(s.Sessions), strconv.Itoa(s.Unserved), res.Action.String(),
				res.Promoted, strconv.Itoa(res.Refilled), strconv.Itoa(res.Reaped),
			})
			// flushed every tick so a ctrl-c keeps the run
			rows.Flush()
		}
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
