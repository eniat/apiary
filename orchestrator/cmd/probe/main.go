package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func main() {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	list, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Fatalf("list: %v", err)
	}

	for _, c := range list {
		name := strings.TrimPrefix(c.Names[0], "/")
		fmt.Printf("%s  %s  %s\n", c.ID[:12], name, c.State)
	}
}
