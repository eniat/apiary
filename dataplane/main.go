package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
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
	dark := flag.String("dark", "172.30.99.0/24", "dark prefix")
	lab := flag.String("lab", "enp0s8", "lab facing interface for the darknet hook")
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

	dk, err := darkKey(*dark)
	if err != nil {
		log.Fatalf("dark: %v", err)
	}
	if err := objs.Darknet.Put(&dk, uint8(1)); err != nil {
		log.Fatalf("darknet put: %v", err)
	}
	log.Printf("dark prefix %s", *dark)

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

	cleanup, how, err := attach(objs.TcRedirect, objs.TcReturn, iface, ifName)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer cleanup()
	defer clearMap(objs.RedirectTargets, new(redirectTarget), "redirect")
	defer clearMap(objs.Flagged, new(redirectFlag), "flag")
	defer printStats(objs.RedirectStats)

	darkCleanup, err := attachDark(objs.TcDarknet, *lab)
	if err != nil {
		log.Fatalf("darknet attach: %v", err)
	}
	defer darkCleanup()
	log.Printf("darknet hook on %s ingress", *lab)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()
	go consume(rd)

	log.Printf("attached to %s via %s, ctrl-c to detach", ifName, how)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	log.Printf("caught %v, detaching", <-c)
}

func printStats(m *ebpf.Map) {
	var per []redirectStats
	if err := m.Lookup(uint32(0), &per); err != nil {
		log.Printf("stats: %v", err)
		return
	}
	var ns, pkts uint64
	for _, s := range per {
		ns += s.Ns
		pkts += s.Pkts
	}
	if pkts == 0 {
		log.Print("no packets redirected")
		return
	}
	log.Printf("redirected %d packets mean %d ns in program", pkts, ns/pkts)
}

func darkKey(cidr string) (redirectDarkKey, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return redirectDarkKey{}, err
	}
	ip := n.IP.To4()
	if ip == nil {
		return redirectDarkKey{}, fmt.Errorf("not an ipv4 prefix: %s", cidr)
	}
	ones, _ := n.Mask.Size()
	k := redirectDarkKey{Prefixlen: uint32(ones)}
	copy(k.Addr[:], ip)
	return k, nil
}

func clearMap(m *ebpf.Map, val any, what string) {
	var key uint32
	var keys []uint32
	it := m.Iterate()
	for it.Next(&key, val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			log.Printf("%s delete %d: %v", what, k, err)
		}
	}
	log.Printf("cleared %d %s rows", len(keys), what)
}

func ipText(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func consume(rd *ringbuf.Reader) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		var e redirectEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("ringbuf decode: %v", err)
			continue
		}
		log.Printf("flagged %s touched %s reason %d ns %d", ipText(e.Saddr), ipText(e.Daddr), e.Reason, e.Ns)
	}
}
