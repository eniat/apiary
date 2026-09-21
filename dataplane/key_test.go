package main

import (
	"encoding/binary"
	"testing"
)

// assert bytes, not the integer
func TestIPKeyBytes(t *testing.T) {
	tests := []struct {
		in   string
		want [4]byte
	}{
		{"10.10.10.20", [4]byte{0x0a, 0x0a, 0x0a, 0x14}},
		{"172.30.0.3", [4]byte{0xac, 0x1e, 0x00, 0x03}},
		{"0.0.0.0", [4]byte{0x00, 0x00, 0x00, 0x00}},
		{"255.255.255.255", [4]byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		k, err := ipKey(tt.in)
		if err != nil {
			t.Fatalf("ipKey(%s): %v", tt.in, err)
		}
		var got [4]byte
		binary.LittleEndian.PutUint32(got[:], k)
		if got != tt.want {
			t.Errorf("ipKey(%s) = % x, want % x", tt.in, got[:], tt.want[:])
		}
	}
}

func TestIPKeyRejects(t *testing.T) {
	for _, s := range []string{"", "nope", "::1", "10.10.10", "10.10.10.256"} {
		if _, err := ipKey(s); err == nil {
			t.Errorf("ipKey(%q) accepted", s)
		}
	}
}

// prefixlen is host order. the address is network order
func TestDarkKey(t *testing.T) {
	k, err := darkKey("172.30.99.0/24")
	if err != nil {
		t.Fatalf("darkKey: %v", err)
	}
	if k.Prefixlen != 24 {
		t.Errorf("prefixlen = %d, want 24", k.Prefixlen)
	}
	if want := [4]uint8{0xac, 0x1e, 0x63, 0x00}; k.Addr != want {
		t.Errorf("addr = % x, want % x", k.Addr, want)
	}
}

func TestDarkKeyRejects(t *testing.T) {
	for _, s := range []string{"", "172.30.99.0", "172.30.99.0/33", "::1/128"} {
		if _, err := darkKey(s); err == nil {
			t.Errorf("darkKey(%q) accepted", s)
		}
	}
}

func TestIPTextRoundTrip(t *testing.T) {
	for _, s := range []string{"10.10.10.20", "172.30.99.10", "0.0.0.0"} {
		k, err := ipKey(s)
		if err != nil {
			t.Fatalf("ipKey(%s): %v", s, err)
		}
		if got := ipText(k); got != s {
			t.Errorf("ipText(ipKey(%s)) = %s", s, got)
		}
	}
}
