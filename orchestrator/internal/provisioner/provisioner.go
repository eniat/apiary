// Package provisioner creates and tracks the honeypot pool.
package provisioner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	dnet "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

// cowrie writes as this uid and fails silently if it cannot
const cowrieUID = 999

// pointer because docker treats unset and zero differently
var pidsLimit int64 = 128

var ErrPoolEmpty = errors.New("warm pool empty")

type Provisioner struct {
	cli     *client.Client
	image   string
	network string
	logRoot string

	readyTimeout time.Duration
	readyBackoff time.Duration
	drainTimeout time.Duration

	// seccomp profile json, empty leaves dockers default in place
	Seccomp string

	// apparmor profile name, it must already be loaded on the host
	AppArmor string

	// fires once a honeypot has an address but before it is ready. experiments only
	OnInspect func(*apiary.Honeypot)

	mu   sync.Mutex
	pots map[string]*apiary.Honeypot
}

func New(cli *client.Client, img, network, logRoot string) *Provisioner {
	return &Provisioner{
		cli:     cli,
		image:   img,
		network: network,
		logRoot: logRoot,
		pots:    map[string]*apiary.Honeypot{},

		readyTimeout: 60 * time.Second,
		readyBackoff: 100 * time.Millisecond,
		drainTimeout: 10 * time.Second,
	}
}

var _ apiary.Provisioner = (*Provisioner)(nil)

// pull once then start n in parallel or the pool costs n cold starts
func (p *Provisioner) Create(ctx context.Context, n int) ([]*apiary.Honeypot, error) {
	if err := p.pull(ctx); err != nil {
		return nil, err
	}

	hps := make([]*apiary.Honeypot, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hps[i], errs[i] = p.one(ctx)
			// a honeypot that never answers is destroyed not leaked
			if errs[i] != nil && hps[i] != nil {
				p.Discard(ctx, hps[i])
				hps[i] = nil
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			continue
		}
		// never leak half a pool
		for _, hp := range hps {
			if hp != nil {
				p.Discard(ctx, hp)
			}
		}
		return nil, fmt.Errorf("honeypot %d: %w", i, err)
	}

	p.mu.Lock()
	for _, hp := range hps {
		p.pots[hp.ID] = hp
	}
	p.mu.Unlock()
	return hps, nil
}

func (p *Provisioner) one(ctx context.Context) (*apiary.Honeypot, error) {
	name, err := potName()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(p.logRoot, name, "log")
	state := filepath.Join(p.logRoot, name, "state")
	for _, d := range []string{dir, state, filepath.Join(state, "tty")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chown(d, cowrieUID, cowrieUID); err != nil {
			return nil, err
		}
	}

	resp, err := p.cli.ContainerCreate(ctx,
		&container.Config{Image: p.image},
		&container.HostConfig{
			// cowrie runs as 999 so this empties the bounding set not the effective one
			CapDrop: []string{"ALL"},
			// docker diff shows cowrie writes nothing outside its binds
			ReadonlyRootfs: true,
			SecurityOpt:    securityOpt(p.Seccomp, p.AppArmor),
			// one honeypot cannot take the host down with it
			Resources: container.Resources{
				NanoCPUs:    500000000,
				Memory:      256 * 1024 * 1024,
				MemorySwap:  256 * 1024 * 1024,
				PidsLimit:   &pidsLimit,
				BlkioWeight: 500,
			},
			Binds: []string{
				dir + ":" + apiary.CowrieLogDir,
				state + ":" + apiary.CowrieStateDir,
			}},
		&dnet.NetworkingConfig{
			EndpointsConfig: map[string]*dnet.EndpointSettings{p.network: {}},
		},
		nil,
		name,
	)
	if err != nil {
		return nil, err
	}

	hp := &apiary.Honeypot{ID: name, State: apiary.Creating}
	if err := p.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return hp, err
	}
	if err := p.inspect(ctx, hp); err != nil {
		return hp, err
	}
	if p.OnInspect != nil {
		p.OnInspect(hp)
	}
	if _, err := waitReady(ctx, dialTCP, net.JoinHostPort(hp.IP.String(), strconv.Itoa(potPort)), p.readyTimeout, p.readyBackoff); err != nil {
		return hp, err
	}
	hp.State = apiary.Warm
	return hp, nil
}

// read at start. addresses macs and veths are reassigned every time
func (p *Provisioner) inspect(ctx context.Context, hp *apiary.Honeypot) error {
	info, err := p.cli.ContainerInspect(ctx, hp.ID)
	if err != nil {
		return err
	}
	ep, ok := info.NetworkSettings.Networks[p.network]
	if !ok {
		return fmt.Errorf("%s not on %s", hp.ID, p.network)
	}
	hp.IP = net.ParseIP(ep.IPAddress)
	if hp.IP == nil {
		return fmt.Errorf("%s has no address", hp.ID)
	}
	mac, err := net.ParseMAC(ep.MacAddress)
	if err != nil {
		return err
	}
	hp.MAC = mac

	ifx, err := iflink(info.State.Pid)
	if err != nil {
		return err
	}
	hp.Ifindex = ifx
	return nil
}

// the container eth0 points at the host side veth
func iflink(pid int) (uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/sys/class/net/eth0/iflink", pid))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// a state change now. it becomes a map write once the registrar exists
func (p *Provisioner) Promote(ctx context.Context) (*apiary.Honeypot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, hp := range p.pots {
		if hp.State == apiary.Warm {
			hp.State = apiary.Live
			hp.LastSeen = time.Now()
			return hp, nil
		}
	}
	return nil, ErrPoolEmpty
}

// logs under logRoot survive on purpose. archival is not this
func (p *Provisioner) Discard(ctx context.Context, hp *apiary.Honeypot) error {
	err := p.cli.ContainerRemove(ctx, hp.ID, container.RemoveOptions{Force: true})
	p.mu.Lock()
	delete(p.pots, hp.ID)
	p.mu.Unlock()
	hp.State = apiary.Dead
	return err
}

func (p *Provisioner) List() []*apiary.Honeypot {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*apiary.Honeypot, 0, len(p.pots))
	for _, hp := range p.pots {
		out = append(out, hp)
	}
	return out
}

// create does not pull so a clean host gets no such image
func (p *Provisioner) pull(ctx context.Context) error {
	// a local image makes the pull optional. with the cable off it only times out
	if _, err := p.cli.ImageInspect(ctx, p.image); err == nil {
		return nil
	}

	rc, err := p.cli.ImagePull(ctx, p.image, image.PullOptions{})
	if err != nil {
		return err
	}
	defer rc.Close()
	// draining waits for the pull to finish
	_, err = io.Copy(io.Discard, rc)
	return err
}

func potName() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ap-hp-" + hex.EncodeToString(b), nil
}

// LoadSeccomp reads a profile for ContainerCreate which takes json not a path
func (p *Provisioner) LoadSeccomp(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	p.Seccomp = string(b)
	return nil
}

func securityOpt(profile, apparmor string) []string {
	var opt []string
	if profile != "" {
		opt = append(opt, "seccomp="+profile)
	}
	if apparmor != "" {
		opt = append(opt, "apparmor="+apparmor)
	}
	return opt
}
