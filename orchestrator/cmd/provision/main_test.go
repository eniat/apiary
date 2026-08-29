package main

import (
	"net"
	"testing"
	"time"
)

func TestWaitReadyListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if err := waitReady(ln.Addr().String(), 2*time.Second); err != nil {
		t.Errorf("waitReady() = %v, want nil", err)
	}
}

func TestWaitReadyClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if err := waitReady(addr, 300*time.Millisecond); err == nil {
		t.Error("waitReady() = nil, want timeout error")
	}
}
