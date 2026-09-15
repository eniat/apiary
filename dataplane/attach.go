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

const pinPath = "/sys/fs/bpf/apiary-tc-redirect"

func attach(prog *ebpf.Program, iface *net.Interface, name string) (func(), string, error) {
	if os.Getenv("APIARY_ATTACH") != "tc" {
		c, err := attachTCX(prog, iface.Index)
		if err == nil {
			return c, "tcx", nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return nil, "", err
		}
	}
	c, err := attachTC(prog, name)
	if err != nil {
		return nil, "", err
	}
	return c, "tc", nil
}

func attachTCX(prog *ebpf.Program, idx int) (func(), error) {
	var open []io.Closer
	for _, at := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
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

// tc needs the program on bpffs, it cannot take a file descriptor
func attachTC(prog *ebpf.Program, name string) (func(), error) {
	os.Remove(pinPath)
	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pin: %w", err)
	}
	_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()
	for _, dir := range []string{"ingress", "egress"} {
		out, err := exec.Command("tc", "filter", "add", "dev", name, dir,
			"bpf", "da", "pinned", pinPath).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("tc filter %s: %w: %s", dir, err, out)
		}
	}
	return func() {
		_ = exec.Command("tc", "qdisc", "del", "dev", name, "clsact").Run()
		os.Remove(pinPath)
	}, nil
}
