// Package registrar writes honeypot rows into the redirect map.
package registrar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

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

// which honeypot a source is tied to and when it last mattered
type bind struct {
	id   string
	seen time.Time
}

type Registrar struct {
	m *ebpf.Map

	mu sync.Mutex
	// source ip to binding. the map itself cannot be read backwards
	srcs map[string]bind
}

func Open(path string) (*Registrar, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Registrar{m: m, srcs: map[string]bind{}}, nil
}

func (r *Registrar) Close() error {
	return r.m.Close()
}

var _ apiary.Registrar = (*Registrar)(nil)

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
	if err := r.m.Put(k, v); err != nil {
		return err
	}
	r.mu.Lock()
	r.srcs[src.String()] = bind{id: hp.ID, seen: time.Now()}
	r.mu.Unlock()
	return nil
}

// a row that is already gone is not an error
func (r *Registrar) Deregister(src net.IP) error {
	k, err := Key(src)
	if err != nil {
		return err
	}
	if err := r.m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	r.mu.Lock()
	delete(r.srcs, src.String())
	r.mu.Unlock()
	return nil
}

func (r *Registrar) SourcesFor(id string) []net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []net.IP
	for s, b := range r.srcs {
		if b.id == id {
			out = append(out, net.ParseIP(s))
		}
	}
	return out
}

// an engagement outlives the session so a bound honeypot is not idle
func (r *Registrar) Bound(id string, now time.Time, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.srcs {
		if b.id == id && now.Sub(b.seen) <= ttl {
			return true
		}
	}
	return false
}

// a live session keeps the binding alive
func (r *Registrar) Refresh(id string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s, b := range r.srcs {
		if b.id == id {
			b.seen = now
			r.srcs[s] = b
		}
	}
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
