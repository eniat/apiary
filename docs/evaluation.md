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

## detection to registration

Time from the kernel flagging a source to the redirect row being written by the loader. Ring buffer wakeup plus decode plus map write.

| samples | mean | min | max |
|---|---|---|---|
| 10 | 3.25 ms | 1.38 ms | 5.23 ms |

Kernel timestamps `bpf_ktime_get_ns` on the flagging packet and the loader reads `CLOCK_MONOTONIC` after the map write. Same clock so no skew. Ten dark touches with the flagged row deleted between each.

The map write is microseconds. Nearly all of this is waking the reader goroutine on a 2 vCPU VM, which is what the 4 ms spread across identical work shows. Treat it as a scheduling figure rather than a ring buffer one.

Excludes the attacker's own delay before its next connection, which dominates any end to end figure and measures the attacker not the system.

Adds to the fidelity side channel: a flagged source meets this delay once, on its first connection after being flagged.

## cold start

Twenty samples of container create through to a TCP connection the honeypot accepts, taken in three batches on an otherwise idle defender.

| batch | n | min | median | mean | max | sd |
|-------|----|-------|--------|-------|--------|-------|
| 1     | 10 | 2.732 | 7.168  | 6.587 | 10.335 | 2.695 |
| 2     | 5  | 2.782 | 2.845  | 2.844 | 2.886  | 0.035 |
| 3     | 5  | 3.974 | 9.502  | 9.050 | 11.556 | 2.746 |
| all   | 20 | 2.732 | 6.346  | 6.267 | 11.556 | 3.230 |

- Measured by `orchestrator/cmd/coldstart`, which times create through to an accepted dial then destroys and repeats
- The spread matters more than the mean. Same command and same host minutes apart gave a batch at 2.844 with almost no variance and a batch at 9.050 with a 7.6 second range
- A honeypot created when the attack arrives cant be promised to that attacker. At the ninetieth percentile the wait is 10.3 seconds and no client waits that long
- Registering before ready was tested separately and refused nothing across five attempts, so the loss is in the create and not in the last moment before the listener comes up

### open: resets during scale events

- With the data plane attached, 27 connections to a live decoy were refused across five create and destroy cycles, in five clusters of 0.67 to 0.93 seconds, each opening within 0.26 seconds of a teardown and closing shortly after the next create
- The same cycle with the data plane detached refused none of 300 connections
- Source port reuse is ruled out. 494 connections used 494 distinct ports, so no stale flow entry is involved
- Cause not established. Recorded because it reproduces and because it attributes a reset to the decoy that the decoy did not send
