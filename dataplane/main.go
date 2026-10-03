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
	"golang.org/x/sys/unix"
)

func ipKey(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("not an ipv4 address: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

// the orchestrator opens this by path. it goes when the loader exits
const pinUnserved = "/sys/fs/bpf/apiary-unserved"

func main() {
	src := flag.String("src", "", "attacker source ip, the map key")
	dst := flag.String("dst", "", "honeypot ip")
	mac := flag.String("mac", "", "honeypot mac")
	ifindex := flag.Uint("ifindex", 0, "host side veth ifindex")
	dark := flag.String("dark", "172.30.99.0/24", "dark prefix")
	lab := flag.String("lab", "enp0s8", "lab facing interface for the darknet hook")
	ports := flag.Uint("scan-ports", 10, "distinct ports in the window that flag a source")
	window := flag.Uint("scan-window", 10, "scan window seconds")
	flag.Parse()

	ifName := os.Getenv("APIARY_IFACE")
	if ifName == "" {
		log.Fatal("set APIARY_IFACE, see make iface")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	var objs redirectObjects
	spec, err := loadRedirect()
	if err != nil {
		log.Fatalf("spec: %v", err)
	}
	if err := spec.Variables["scan_ports"].Set(uint32(*ports)); err != nil {
		log.Fatalf("scan_ports: %v", err)
	}
	if err := spec.Variables["scan_window_ns"].Set(uint64(*window) * 1000000000); err != nil {
		log.Fatalf("scan_window_ns: %v", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier:\n%+v", ve)
		}
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()

	os.Remove(pinUnserved)
	if err := objs.Unserved.Pin(pinUnserved); err != nil {
		log.Fatalf("pin unserved: %v", err)
	}
	defer objs.Unserved.Unpin()

	dk, err := darkKey(*dark)
	if err != nil {
		log.Fatalf("dark: %v", err)
	}
	if err := objs.Darknet.Put(&dk, uint8(1)); err != nil {
		log.Fatalf("darknet put: %v", err)
	}
	log.Printf("dark prefix %s", *dark)

	var tgt *redirectTarget
	if *dst != "" {
		daddr, err := ipKey(*dst)
		if err != nil {
			log.Fatalf("dst: %v", err)
		}
		hw, err := net.ParseMAC(*mac)
		if err != nil {
			log.Fatalf("mac: %v", err)
		}
		tgt = &redirectTarget{NewDaddr: daddr, Ifindex: uint32(*ifindex)}
		copy(tgt.NewDmac[:], hw)
	}

	if *src != "" {
		if tgt == nil {
			log.Fatal("-src needs -dst and -mac and -ifindex")
		}
		key, err := ipKey(*src)
		if err != nil {
			log.Fatalf("src: %v", err)
		}
		if err := objs.RedirectTargets.Put(key, tgt); err != nil {
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
	go consume(rd, objs.RedirectTargets, tgt)

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

func consume(rd *ringbuf.Reader, targets *ebpf.Map, tgt *redirectTarget) {
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
		if tgt == nil {
			continue
		}
		if err := targets.Put(e.Saddr, tgt); err != nil {
			log.Printf("register %s: %v", ipText(e.Saddr), err)
			continue
		}
		log.Printf("registered %s to %s in %d ns", ipText(e.Saddr), ipText(tgt.NewDaddr), monotonicNs()-e.Ns)
	}
}

// same clock as bpf_ktime_get_ns so event timestamps subtract cleanly
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1000000000 + uint64(ts.Nsec)
}
