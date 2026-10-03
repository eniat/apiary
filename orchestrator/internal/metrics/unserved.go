package metrics

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// the loader pins it here
const UnservedPin = "/sys/fs/bpf/apiary-unserved"

type Unserved struct {
	m    *ebpf.Map
	last uint64
	seen bool
}

func OpenUnserved(path string) (*Unserved, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Unserved{m: m}, nil
}

func (u *Unserved) Close() error {
	return u.m.Close()
}

// flows since the last call
func (u *Unserved) Sample() (uint64, error) {
	var per []uint64
	if err := u.m.Lookup(uint32(0), &per); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range per {
		total += v
	}
	// first read sets the baseline
	if !u.seen {
		u.seen = true
		u.last = total
		return 0, nil
	}
	d := delta(u.last, total)
	u.last = total
	return d, nil
}

// a restarted loader brings a fresh map so the counter can go backwards
func delta(last, now uint64) uint64 {
	if now < last {
		return now
	}
	return now - last
}
