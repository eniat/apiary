package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
)

func main() {
	n := flag.Int("n", 3, "honeypots to create")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	keep := flag.Bool("keep", false, "leave the pool running")
	flag.Parse()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	ctx := context.Background()
	p := provisioner.New(cli, "cowrie/cowrie:latest", "apiary-net", *logs)

	start := time.Now()
	if _, err := p.Create(ctx, *n); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("created %d in %s\n", *n, time.Since(start).Round(time.Millisecond))

	for _, hp := range p.List() {
		fmt.Printf("%s %s %s ifindex %d state %d\n", hp.ID, hp.IP, hp.MAC, hp.Ifindex, hp.State)
	}

	hp, err := p.Promote(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("promoted %s\n", hp.ID)

	if *keep {
		return
	}
	for _, hp := range p.List() {
		if err := p.Discard(ctx, hp); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("discarded")
}
