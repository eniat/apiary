package main

import (
	"errors"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifName := os.Getenv("APIARY_IFACE")
	if ifName == "" {
		log.Fatal("set APIARY_IFACE, see make iface")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	var objs redirectObjects
	if err := loadRedirectObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier:\n%+v", ve)
		}
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("interface %s: %v", ifName, err)
	}

	for _, at := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.TcRedirect,
			Attach:    at,
		})
		if err != nil {
			log.Fatalf("attach %v: %v", at, err)
		}
		defer l.Close()
	}

	log.Printf("attached to %s, ctrl-c to detach", ifName)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
