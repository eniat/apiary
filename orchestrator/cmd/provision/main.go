package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

const (
	netName   = "apiary-net"
	imageName = "cowrie/cowrie:latest"
	probeName = "ap-probe"
)

// address exists before the service listens
func waitReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s not ready in %s", addr, timeout)
}

func main() {
	start := time.Now()
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	resp, err := cli.ContainerCreate(ctx,
		&container.Config{Image: imageName},
		&container.HostConfig{},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{netName: {}},
		},
		nil,
		probeName,
	)
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	id := resp.ID
	fmt.Printf("created %s\n", id[:12])

	// destroy on every exit path
	defer func() {
		if err := cli.ContainerRemove(ctx, id, container.RemoveOptions{Force: true}); err != nil {
			log.Printf("remove: %v", err)
			return
		}
		fmt.Println("removed")
	}()

	if err := cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		log.Printf("start: %v", err)
		return
	}

	info, err := cli.ContainerInspect(ctx, id)
	if err != nil {
		log.Printf("inspect: %v", err)
		return
	}

	ep := info.NetworkSettings.Networks[netName]
	addr := net.JoinHostPort(ep.IPAddress, "2222")

	if err := waitReady(addr, 30*time.Second); err != nil {
		log.Printf("ready: %v", err)
		return
	}

	fmt.Printf("ready %s mac %s after %s\n", addr, ep.MacAddress, time.Since(start).Round(time.Millisecond))
}
