package registrar

import (
	"net"
	"testing"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

func TestKey(t *testing.T) {
	got, err := Key(net.ParseIP("172.30.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x09001EAC {
		t.Errorf("got %#x, want 0x09001EAC", got)
	}
}

func TestKeyRejectsV6(t *testing.T) {
	if _, err := Key(net.ParseIP("fe80::1")); err == nil {
		t.Error("want an error, got nil")
	}
}

func TestRow(t *testing.T) {
	mac, err := net.ParseMAC("02:42:ac:1e:00:03")
	if err != nil {
		t.Fatal(err)
	}
	hp := &apiary.Honeypot{ID: "a", IP: net.ParseIP("172.30.0.3"), MAC: mac, Ifindex: 12}

	got, err := row(hp)
	if err != nil {
		t.Fatal(err)
	}
	if got.NewDaddr != 0x03001EAC {
		t.Errorf("got daddr %#x, want 0x03001EAC", got.NewDaddr)
	}
	if got.Ifindex != 12 {
		t.Errorf("got ifindex %d, want 12", got.Ifindex)
	}
	if got.NewDMAC != [6]byte{0x02, 0x42, 0xac, 0x1e, 0x00, 0x03} {
		t.Errorf("got mac %x", got.NewDMAC)
	}
}

func TestRowRejectsIncomplete(t *testing.T) {
	mac, _ := net.ParseMAC("02:42:ac:1e:00:03")
	cases := []struct {
		name string
		hp   *apiary.Honeypot
	}{
		{"no ifindex", &apiary.Honeypot{IP: net.ParseIP("172.30.0.3"), MAC: mac}},
		{"no mac", &apiary.Honeypot{IP: net.ParseIP("172.30.0.3"), Ifindex: 12}},
		{"no address", &apiary.Honeypot{MAC: mac, Ifindex: 12}},
	}
	for _, c := range cases {
		if _, err := row(c.hp); err == nil {
			t.Errorf("%s: want an error, got nil", c.name)
		}
	}
}
