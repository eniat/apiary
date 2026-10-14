package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
	"github.com/eniat/apiary/orchestrator/internal/registrar"
)

func main() {
	n := flag.Int("n", 10, "promotions to measure")
	src := flag.String("src", "10.10.10.20", "attacker source ip")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	pin := flag.String("pin", registrar.RedirectPin, "pinned redirect map")
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

	start := time.Now()
	if _, err := p.Create(ctx, *n); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pool of %d warm in %s\n\n", *n, time.Since(start).Round(time.Millisecond))

	reg, err := registrar.Open(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer reg.Close()

	took := make([]time.Duration, 0, *n)
	for i := range *n {
		t0 := time.Now()
		hp, err := p.Promote(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if err := reg.Register(ip, hp); err != nil {
			log.Fatal(err)
		}
		d := time.Since(t0)
		took = append(took, d)
		fmt.Printf("%2d promote and register %s %s\n", i+1, hp.ID, d.Round(time.Microsecond))
	}

	report(took)

	if err := reg.Deregister(ip); err != nil {
		log.Print(err)
	}
	for _, hp := range p.List() {
		if err := p.Discard(ctx, hp); err != nil {
			log.Print(err)
		}
	}
	fmt.Println("torn down")
}

func report(d []time.Duration) {
	if len(d) == 0 {
		return
	}
	lo, hi, sum := d[0], d[0], time.Duration(0)
	for _, v := range d {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
		sum += v
	}
	fmt.Printf("\nn %d min %s mean %s max %s\n",
		len(d), lo.Round(time.Microsecond), (sum / time.Duration(len(d))).Round(time.Microsecond), hi.Round(time.Microsecond))
}
