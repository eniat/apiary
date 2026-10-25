package metrics

import "testing"

func TestCPUPct(t *testing.T) {
	cases := []struct {
		name                   string
		cpu0, cpu1, sys0, sys1 uint64
		cpus                   uint32
		want                   float64
		ok                     bool
	}{
		{"half of one cpu", 0, 500, 0, 1000, 1, 50, true},
		{"busy on four", 0, 1000, 0, 1000, 4, 400, true},
		{"idle", 500, 500, 0, 1000, 2, 0, true},
		{"no system delta", 0, 500, 1000, 1000, 1, 0, false},
		{"counter went back", 500, 0, 0, 1000, 1, 0, false},
		{"no cpus reported", 0, 500, 0, 1000, 0, 0, false},
	}
	for _, c := range cases {
		got, ok := cpuPct(c.cpu0, c.cpu1, c.sys0, c.sys1, c.cpus)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %v %v, want %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}
