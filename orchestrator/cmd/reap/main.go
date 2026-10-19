package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/apiary"
	"github.com/eniat/apiary/orchestrator/internal/metrics"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
	"github.com/eniat/apiary/orchestrator/internal/reaper"
	"github.com/eniat/apiary/orchestrator/internal/registrar"
)

func main() {
	src := flag.String("src", "10.10.10.20", "attacker source ip")
	grace := flag.Duration("grace", 30*time.Second, "idle time before a honeypot is destroyed")
	affinity := flag.Duration("affinity", 5*time.Minute, "how long a source keeps its honeypot after the last session")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	pin := flag.String("pin", registrar.RedirectPin, "pinned redirect map")
	archive := flag.String("archive", "/var/lib/apiary/archive", "durable log archive root")
	ticks := flag.Int("ticks", 30, "reap attempts")
	flag.Parse()

	ip := net.ParseIP(*src)
	if ip == nil {
		log.Fatalf("bad source %s", *src)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	ctx := context.Background()
	p := provisioner.New(cli, "cowrie/cowrie:latest", "apiary-net", *logs)
	if _, err := p.Create(ctx, 2); err != nil {
		log.Fatal(err)
	}

	r, err := registrar.Open(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// both live. only one carries a redirect row
	first, err := p.Promote(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := p.Promote(ctx); err != nil {
		log.Fatal(err)
	}
	if err := r.Register(ip, first); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("registered %s to %s %s\n", ip, first.ID, first.IP)
	fmt.Printf("from the attacker: ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s\n", first.IP)

	rp := reaper.New(p, r, reaper.DirArchiver{LogRoot: *logs, Dest: *archive}, *grace, *affinity, func(err error) { log.Print(err) })
	sess := metrics.NewSessions(cli, 5*time.Minute)

	for range *ticks {
		hps := p.List()
		if len(hps) == 0 {
			fmt.Println("pool empty")
			return
		}

		var ids []string
		for _, hp := range hps {
			if hp.State == apiary.Live {
				ids = append(ids, hp.ID)
			}
		}

		now := time.Now()
		counts := map[string]int{}
		cs, err := sess.Sample(ctx, ids, now)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range cs {
			counts[c.ID] = c.Sessions
		}

		n, err := rp.ReapIdle(ctx, now, counts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s pool %d sessions %v reaped %d\n", now.Format("15:04:05"), len(ids), counts, n)
		time.Sleep(5 * time.Second)
	}
}
