package main

import (
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

const (
	netName   = "apiary-net"
	imageName = "cowrie/cowrie:latest"
	probeName = "ap-probe"
)

func main() {
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

	// destroy on every exit path, including the failures below
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
	fmt.Printf("honeypot at %s mac %s\n", ep.IPAddress, ep.MacAddress)
}
