package metrics

import (
	"testing"
	"time"
)

func logLine(eventid, session, ts string) []byte {
	return []byte(`{"eventid":"` + eventid + `","session":"` + session +
		`","timestamp":"` + ts + `","src_ip":"10.10.10.20"}` + "\n")
}

func TestSessionCount(t *testing.T) {
	const stale = 5 * time.Minute
	seen := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	later := seen.Add(10 * time.Minute)

	connect := logLine("cowrie.session.connect", "aaaa", "2026-10-01T12:00:00.100000Z")
	command := logLine("cowrie.command.input", "aaaa", "2026-10-01T12:00:30.000000Z")
	closed := logLine("cowrie.session.closed", "aaaa", "2026-10-01T12:01:00.000000Z")
	second := logLine("cowrie.session.connect", "bbbb", "2026-10-01T12:00:05.000000Z")
	orphan := logLine("cowrie.session.closed", "cccc", "2026-10-01T12:00:05.000000Z")
	refresh := logLine("cowrie.command.input", "aaaa", "2026-10-01T12:09:00.000000Z")

	cases := []struct {
		name  string
		lines [][]byte
		now   time.Time
		want  int
	}{
		{"one open", [][]byte{connect}, seen, 1},
		{"opened then closed", [][]byte{connect, closed}, seen, 0},
		{"two at once", [][]byte{connect, second}, seen, 2},
		{"command does not double count", [][]byte{connect, command}, seen, 1},
		{"close without an open", [][]byte{orphan}, seen, 0},
		{"nul bytes skipped", [][]byte{connect, []byte("\x00\x00\x00\n")}, seen, 1},
		{"not json skipped", [][]byte{connect, []byte("half a li\n")}, seen, 1},
		{"no session field skipped", [][]byte{connect, []byte(`{"eventid":"cowrie.log.closed"}` + "\n")}, seen, 1},
		{"stale open presumed closed", [][]byte{connect}, later, 0},
		{"refreshed inside the window", [][]byte{connect, refresh}, later, 1},
	}

	for _, c := range cases {
		open := map[string]time.Time{}
		for _, l := range c.lines {
			apply(open, l, seen)
		}
		if got := expire(open, c.now, stale); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}
