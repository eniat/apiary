package metrics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/client"
)

// cowrie log paths inside the image
const (
	cowrieLogDir  = "/cowrie/cowrie-git/var/log/cowrie"
	cowrieLogFile = "cowrie.json"
)

type Count struct {
	ID       string
	Sessions int
}

// only the fields the count needs
type event struct {
	EventID   string `json:"eventid"`
	Session   string `json:"session"`
	Timestamp string `json:"timestamp"`
}

// read position plus open sessions
type tail struct {
	path   string
	offset int64
	open   map[string]time.Time
}

type Sessions struct {
	cli   *client.Client
	stale time.Duration
	mu    sync.Mutex
	tails map[string]*tail
}

// stale must stay above cowrie idle_timeout
func NewSessions(cli *client.Client, stale time.Duration) *Sessions {
	return &Sessions{cli: cli, stale: stale, tails: map[string]*tail{}}
}

func (s *Sessions) Sample(ctx context.Context, ids []string, now time.Time) ([]Count, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Count, len(ids))
	for i, id := range ids {
		out[i].ID = id
		t, err := s.tailFor(ctx, id)
		if err != nil {
			return out, fmt.Errorf("%s: %w", id, err)
		}
		if err := t.read(now); err != nil {
			return out, fmt.Errorf("%s: %w", id, err)
		}
		out[i].Sessions = expire(t.open, now, s.stale)
	}
	return out, nil
}

// inspect once per container
func (s *Sessions) tailFor(ctx context.Context, id string) (*tail, error) {
	if t, ok := s.tails[id]; ok {
		return t, nil
	}
	info, err := s.cli.ContainerInspect(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, m := range info.Mounts {
		if m.Destination == cowrieLogDir {
			t := &tail{path: filepath.Join(m.Source, cowrieLogFile), open: map[string]time.Time{}}
			s.tails[id] = t
			return t, nil
		}
	}
	return nil, fmt.Errorf("no bind mount for %s", cowrieLogDir)
}

// read only what is new
func (t *tail) read(now time.Time) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	// rotation leaves a shorter file
	if fi.Size() < t.offset {
		t.offset = 0
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			// half written line gets read next tick
			return nil
		}
		if err != nil {
			return err
		}
		t.offset += int64(len(line))
		apply(t.open, line, now)
	}
}

// closed ends a session everything else refreshes
func apply(open map[string]time.Time, line []byte, seen time.Time) {
	var e event
	if err := json.Unmarshal(line, &e); err != nil || e.Session == "" {
		return
	}
	if e.EventID == "cowrie.session.closed" {
		delete(open, e.Session)
		return
	}
	ts, err := time.Parse(time.RFC3339, e.Timestamp)
	if err != nil {
		ts = seen
	}
	open[e.Session] = ts
}

// silence counts as closed
func expire(open map[string]time.Time, now time.Time, stale time.Duration) int {
	for sid, last := range open {
		if now.Sub(last) > stale {
			delete(open, sid)
		}
	}
	return len(open)
}
