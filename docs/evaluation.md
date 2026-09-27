# evaluation

## redirect cost

Time in the tc program per redirected packet.

| build | packets | mean |
|---|---|---|
| with debug bpf_printk | 58 | 12376 ns |
| with debug bpf_printk | 58 | 12630 ns |
| printk removed | 57 | 3188 ns |

Method: `bpf_ktime_get_ns` at program entry and again before `bpf_redirect`,
accumulated in a per-cpu array, mean printed on exit.

Covers parse, map lookup, both checksum patches, IP and MAC rewrite.
Excludes veth transmit and scheduling after the program returns, so a floor
on added latency not the full path cost.

`bpf_printk` costs roughly 9300 ns per packet. Debug only, never in a
measured build.

Samples are small and sparse, every packet a cold cache hit. 3188 ns is an
upper bound on steady state.

Latency is also a fingerprinting vector. An attacker timing responses could
tell a redirected service from a direct one.

## scan thresholds

A source is flagged at N distinct destination ports inside T seconds. Swept 4 values of N against 3 of T with one run per cell. `evidence/scan-sweep.csv`

| profile | traffic |
|---|---|
| benign | 8 service ports one every 2s |
| fast scan | nmap 200 ports in about 5s |
| slow scan | nmap 25 ports at 1s a port |

- Fast scan flagged in all 12 cells
- Slow scan flagged at 5/10 and 5/30 and 10/10 and 10/30 only
- Benign flagged at 5/30 only

**Chosen: 10 ports in 10s.** It misses benign and catches both scans. Benign peaks near 5 distinct ports per window so the threshold is double the rate it must ignore. 5/10 gives the same outcomes with no margin and 10/30 is slower to fire for nothing.

Misses anything under 1 port per second. The 25 port slow scan ran past 30s which is why 20/30 never accumulated 20 ports in one window.

One run per cell and one benign profile from one host. Outcomes are flagged or not rather than rates.
