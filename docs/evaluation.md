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
