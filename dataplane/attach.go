package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	pinRedirect = "/sys/fs/bpf/apiary-tc-redirect"
	pinDarknet  = "/sys/fs/bpf/apiary-tc-darknet"
)

func attach(prog *ebpf.Program, iface *net.Interface, name string) (func(), string, error) {
	if os.Getenv("APIARY_ATTACH") != "tc" {
		c, err := attachTCX(prog, iface.Index, ebpf.AttachTCXIngress, ebpf.AttachTCXEgress)
		if err == nil {
			return c, "tcx", nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return nil, "", err
		}
	}
	c, err := attachTC(prog, name, pinRedirect, "ingress", "egress")
	if err != nil {
		return nil, "", err
	}
	return c, "tc", nil
}

// ingress only. dark traffic never reaches the bridge
func attachDark(prog *ebpf.Program, name string) (func(), error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}
	if os.Getenv("APIARY_ATTACH") != "tc" {
		c, err := attachTCX(prog, iface.Index, ebpf.AttachTCXIngress)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return nil, err
		}
	}
	return attachTC(prog, name, pinDarknet, "ingress")
}

func attachTCX(prog *ebpf.Program, idx int, ats ...ebpf.AttachType) (func(), error) {
	var open []io.Closer
	for _, at := range ats {
		l, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: prog, Attach: at})
		if err != nil {
			for _, c := range open {
				c.Close()
			}
			return nil, err
		}
		open = append(open, l)
	}
	return func() {
		for _, c := range open {
			c.Close()
		}
	}, nil
}

// tc reads the program from bpffs. it cant take a file descriptor
func attachTC(prog *ebpf.Program, name string, pin string, dirs ...string) (func(), error) {
	os.Remove(pin)
	if err := prog.Pin(pin); err != nil {
		return nil, fmt.Errorf("pin: %w", err)
	}
	_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()
	for _, dir := range dirs {
		out, err := exec.Command("tc", "filter", "add", "dev", name, dir,
			"bpf", "da", "pinned", pin).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("tc filter %s: %w: %s", dir, err, out)
		}
	}
	return func() {
		_ = exec.Command("tc", "qdisc", "del", "dev", name, "clsact").Run()
		os.Remove(pin)
	}, nil
}
