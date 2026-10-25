package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/metrics"
)

func main() {
	pin := flag.String("pin", metrics.UnservedPin, "pinned unserved map")
	ticks := flag.Int("ticks", 30, "samples to take")
	flag.Parse()

	u, err := metrics.OpenUnserved(*pin)
	if err != nil {
		log.Fatal(err)
	}
	defer u.Close()

	for range *ticks {
		n, err := u.Sample()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s unserved %d\n", time.Now().Format("15:04:05"), n)
		time.Sleep(2 * time.Second)
	}
}
