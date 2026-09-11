package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func ipKey(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("not an ipv4 address: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func main() {
	src := flag.String("src", "", "attacker source ip, the map key")
	dst := flag.String("dst", "", "honeypot ip")
	mac := flag.String("mac", "", "honeypot mac")
	ifindex := flag.Uint("ifindex", 0, "host side veth ifindex")
	flag.Parse()

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

	if *src != "" {
		key, err := ipKey(*src)
		if err != nil {
			log.Fatalf("src: %v", err)
		}
		daddr, err := ipKey(*dst)
		if err != nil {
			log.Fatalf("dst: %v", err)
		}
		hw, err := net.ParseMAC(*mac)
		if err != nil {
			log.Fatalf("mac: %v", err)
		}
		var t redirectTarget
		t.NewDaddr = daddr
		t.Ifindex = uint32(*ifindex)
		copy(t.NewDmac[:], hw)
		if err := objs.RedirectTargets.Put(key, &t); err != nil {
			log.Fatalf("map put: %v", err)
		}
		log.Printf("mapped %s to %s ifindex %d", *src, *dst, *ifindex)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("interface %s: %v", ifName, err)
	}

	cleanup, how, err := attach(objs.TcRedirect, iface, ifName)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer cleanup()

	log.Printf("attached to %s via %s, ctrl-c to detach", ifName, how)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
