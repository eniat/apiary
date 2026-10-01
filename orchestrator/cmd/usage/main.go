package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/metrics"
)

func main() {
	ids := os.Args[1:]
	if len(ids) == 0 {
		log.Fatal("usage: usage <container>...")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	r := metrics.NewResources(cli)
	for range 10 {
		us, err := r.Sample(context.Background(), ids)
		if err != nil {
			log.Fatal(err)
		}
		for _, u := range us {
			fmt.Printf("%s cpu %.1f%% valid %v mem %d MiB\n", u.ID, u.CPUPct, u.Valid, u.MemBytes>>20)
		}
		time.Sleep(time.Second)
	}
}
