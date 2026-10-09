package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/provisioner"
	"github.com/eniat/apiary/orchestrator/internal/registrar"
)

func main() {
	src := flag.String("src", "10.10.10.20", "attacker source ip, the map key")
	decoy := flag.String("decoy", "ap-cowrie", "container whose address the attacker dials")
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
	if _, err := p.Create(ctx, 1); err != nil {
		log.Fatal(err)
	}

	hp, err := p.Promote(ctx)
	if err != nil {
		log.Fatal(err)
	}

	r, err := registrar.Open(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// register last. traffic can arrive the moment the row lands
	if err := r.Register(ip, hp); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("registered %s to %s %s %s ifindex %d\n", ip, hp.ID, hp.IP, hp.MAC, hp.Ifindex)
	fmt.Printf("logs at %s/%s\n", *logs, hp.ID)

	info, err := cli.ContainerInspect(ctx, *decoy)
	if err == nil {
		fmt.Printf("from the attacker: ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s\n",
			info.NetworkSettings.Networks["apiary-net"].IPAddress)
	}

	fmt.Println("ctrl-c to tear down")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	if err := p.Discard(ctx, hp); err != nil {
		log.Fatal(err)
	}
	fmt.Println("discarded")
}
