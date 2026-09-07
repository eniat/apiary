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
