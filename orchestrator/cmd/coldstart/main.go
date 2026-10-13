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
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
	"github.com/eniat/apiary/orchestrator/internal/registrar"
)

func main() {
	n := flag.Int("n", 10, "cold starts to measure")
	early := flag.Bool("early", false, "register before the honeypot is ready")
	src := flag.String("src", "10.10.10.20", "attacker source ip")
	logs := flag.String("logs", "/var/lib/apiary/logs", "host log root")
	pin := flag.String("pin", registrar.RedirectPin, "pinned redirect map")
	hold := flag.Duration("hold", 0, "pause after each honeypot is ready")
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

	var reg *registrar.Registrar
	if *early {
		reg, err = registrar.Open(*pin)
		if err != nil {
			log.Fatal(err)
		}
		defer reg.Close()

		// the whole point. traffic can arrive at a container with no listener
		p.OnInspect = func(hp *apiary.Honeypot) {
			if err := reg.Register(ip, hp); err != nil {
				log.Print(err)
				return
			}
			fmt.Printf("%s registered %s %s before ready\n", stamp(), hp.ID, hp.IP)
		}
	}

	took := make([]time.Duration, 0, *n)
	for i := range *n {
		fmt.Printf("%s create %d\n", stamp(), i+1)
		start := time.Now()

		hps, err := p.Create(ctx, 1)
		if err != nil {
			log.Fatal(err)
		}
		d := time.Since(start)
		took = append(took, d)
		fmt.Printf("%s ready %s after %s\n", stamp(), hps[0].IP, d.Round(time.Millisecond))

		if *hold > 0 {
			time.Sleep(*hold)
		}
		if reg != nil {
			if err := reg.Deregister(ip); err != nil {
				log.Print(err)
			}
		}
		for _, hp := range p.List() {
			if err := p.Discard(ctx, hp); err != nil {
				log.Print(err)
			}
		}
	}
	report(took)
}

func stamp() string {
	return time.Now().Format("15:04:05.000")
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
		len(d), lo.Round(time.Millisecond), (sum / time.Duration(len(d))).Round(time.Millisecond), hi.Round(time.Millisecond))
}
