package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/metrics"
)

func main() {
	stale := flag.Duration("stale", 5*time.Minute, "silence after which a session counts as closed")
	ticks := flag.Int("ticks", 30, "samples to take")
	flag.Parse()

	ids := flag.Args()
	if len(ids) == 0 {
		log.Fatal("usage: sessions [-stale d] [-ticks n] <container>...")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	s := metrics.NewSessions(cli, *stale)
	for range *ticks {
		cs, err := s.Sample(context.Background(), ids, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range cs {
			fmt.Printf("%s %s sessions %d\n", time.Now().Format("15:04:05"), c.ID, c.Sessions)
		}
		time.Sleep(2 * time.Second)
	}
}
