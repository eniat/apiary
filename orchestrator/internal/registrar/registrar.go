// Package registrar writes honeypot rows into the redirect map.
package registrar

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

// the loader pins it here
const RedirectPin = "/sys/fs/bpf/apiary-redirect"

// mirrors struct target in the data plane byte for byte
type target struct {
	NewDaddr uint32
	Ifindex  uint32
	NewDMAC  [6]byte
	_        [2]byte
}

type Registrar struct {
	m *ebpf.Map
}

func Open(path string) (*Registrar, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Registrar{m: m}, nil
}

func (r *Registrar) Close() error {
	return r.m.Close()
}

// last step before traffic can arrive so the honeypot must already be ready
func (r *Registrar) Register(src net.IP, hp *apiary.Honeypot) error {
	k, err := Key(src)
	if err != nil {
		return err
	}
	v, err := row(hp)
	if err != nil {
		return err
	}
	return r.m.Put(k, v)
}

// network order bytes read back little endian so the sdk writes them unchanged
func Key(ip net.IP) (uint32, error) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not ipv4: %s", ip)
	}
	return binary.LittleEndian.Uint32(v4), nil
}

func row(hp *apiary.Honeypot) (target, error) {
	v4 := hp.IP.To4()
	if v4 == nil {
		return target{}, fmt.Errorf("%s: not ipv4: %s", hp.ID, hp.IP)
	}
	if len(hp.MAC) != 6 {
		return target{}, fmt.Errorf("%s: bad mac: %s", hp.ID, hp.MAC)
	}
	if hp.Ifindex == 0 {
		return target{}, fmt.Errorf("%s: no ifindex", hp.ID)
	}
	t := target{NewDaddr: binary.LittleEndian.Uint32(v4), Ifindex: hp.Ifindex}
	copy(t.NewDMAC[:], hp.MAC)
	return t, nil
}
