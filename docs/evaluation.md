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
Taken before hardening, see scalability.

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

## warm pool

Create to first accepted connection against promote to redirect row written, measured by `cmd/coldstart` and `cmd/promote`.

| path | n | min | mean | max |
|-------------------|----|---------|---------|----------|
| create on demand  | 20 | 2.732 s | 6.267 s | 11.556 s |
| promote from pool | 10 | 5 µs    | 9 µs    | 32 µs    |

Log scale, one mark per decade.

    1µs      10µs     100µs    1ms      10ms     100ms    1s       10s
    |--------|--------|--------|--------|--------|--------|--------|
        * promote 9µs
                                                           * create 6.27s

Confirmed at the control loop with the same attack profile either side. Creating on demand took 5.421618 s on the tick that decided to scale, promoting took 1 µs.

- Roughly seven hundred thousand times faster, and past the point an attacker could notice it
- The first promotion of a run costs 32 µs and the rest cost 5 to 6, which is the first write touching a cold page rather than a pool effect
- Ten warm honeypots start in 21 s, so refilling toward the target is cheap and runs off the control loop rather than on it
- The bottleneck moves rather than disappearing. Trigger to honeypot is now dominated by the control interval, so a five second tick is a five second worst case however fast promotion gets

### what this does not show

- The connection loss a cold start was expected to cause was never reproduced on this topology, so there is no previously failing test that now passes
- Registering a honeypot before it was ready refused nothing across five attempts, so the loss was not in the last moment before the listener came up
- The decoy absorbs anything the redirect does not claim, so a slow scale up here mis-serves an attacker rather than dropping one. With no decoy in the path it would drop them

## scale flapping and hysteresis

Same load profile both times, seeded in `scripts/load.sh`. Same warm pool, same grace. Only the policy changed. Raw ticks in `docs/evidence/`.

| policy | ticks | up | down | reversals | created | destroyed |
|---|---|---|---|---|---|---|
| one threshold at 2 | 30 | 11 | 8 | 14 | 11 | 9 |
| band 1 to 3 | 30 | 3 | 2 | 3 | 3 | 3 |
| band plus 30s down cooldown | 50 | 4 | 4 | 1 | 4 | 4 |

Live honeypots per tick, one threshold.

    17:52:00  1 #
    17:52:05  1 #
    17:52:10  1 #
    17:52:15  2 ##
    17:52:20  1 #
    17:52:25  1 #
    17:52:30  1 #
    17:52:35  2 ##
    17:52:40  1 #
    17:52:45  1 #
    17:52:50  2 ##
    17:52:55  3 ###
    17:53:00  2 ##
    17:53:05  3 ###
    17:53:10  1 #
    17:53:15  1 #
    17:53:20  1 #
    17:53:25  2 ##
    17:53:30  3 ###
    17:53:35  2 ##
    17:53:40  1 #
    17:53:45  2 ##
    17:53:50  1 #
    17:53:55  1 #
    17:54:00  1 #
    17:54:05  2 ##
    17:54:10  1 #
    17:54:15  1 #
    17:54:20  1 #
    17:54:25  2 ##

Live honeypots per tick, with the band.

    18:00:04  1 #
    18:00:09  1 #
    18:00:14  1 #
    18:00:19  1 #
    18:00:24  1 #
    18:00:29  1 #
    18:00:34  1 #
    18:00:39  1 #
    18:00:44  1 #
    18:00:49  1 #
    18:00:54  1 #
    18:00:59  1 #
    18:01:04  2 ##
    18:01:09  2 ##
    18:01:14  1 #
    18:01:19  2 ##
    18:01:24  2 ##
    18:01:29  2 ##
    18:01:34  2 ##
    18:01:39  3 ###
    18:01:44  3 ###
    18:01:49  1 #
    18:01:54  1 #
    18:01:59  1 #
    18:02:04  1 #
    18:02:09  1 #
    18:02:14  1 #
    18:02:19  1 #
    18:02:24  1 #
    18:02:29  1 #


Live honeypots per tick, band plus a 30 second cooldown on scale down.

    13:13:59  1 #
    13:14:04  1 #
    13:14:09  1 #
    13:14:14  1 #
    13:14:19  1 #
    13:14:24  1 #
    13:14:34  2 ##
    13:14:39  2 ##
    13:14:44  2 ##
    13:14:49  2 ##
    13:14:54  3 ###
    13:14:59  3 ###
    13:15:04  3 ###
    13:15:09  4 ####
    13:15:14  4 ####
    13:15:19  4 ####
    13:15:24  4 ####
    13:15:29  4 ####
    13:15:34  5 #####
    13:15:39  5 #####
    13:15:44  5 #####
    13:15:49  5 #####
    13:15:54  5 #####
    13:15:59  5 #####
    13:16:04  4 ####
    13:16:09  4 ####
    13:16:14  4 ####
    13:16:19  4 ####
    13:16:24  4 ####
    13:16:29  4 ####
    13:16:34  3 ###
    13:16:39  3 ###
    13:16:44  3 ###
    13:16:49  3 ###
    13:16:54  3 ###
    13:16:59  3 ###
    13:17:04  2 ##
    13:17:09  2 ##
    13:17:14  2 ##
    13:17:19  2 ##
    13:17:24  2 ##
    13:17:29  2 ##
    13:17:34  2 ##
    13:17:39  1 #
    13:17:44  1 #
    13:17:49  1 #
    13:17:54  1 #
    13:17:59  1 #
    13:18:04  1 #
    13:18:19  1 #

- Reversals are direction changes with holds ignored, so quiet ticks do not pad the count
- The band is 1 to 3, covering 19 of the 30 ticks the first run recorded. Taken from that distribution, not guessed
- A wider band would read better and would be dishonest. The load never exceeds 4, so an up threshold of 4 is not damping, it is scaling switched off
- A band narrower than the swing in the signal changes nothing. There is a unit test holding that line so it is not quietly forgotten
- The cost is response time. Three unserved flows now hold instead of scaling, so a genuine ramp is served at least a tick later
- Both tails stay live so the band alone only damps. A minimum interval between actions removes the rest
- The cooldown is asymmetric. Scaling up late loses an attacker, scaling down late costs a container, so up is free and down waits 30 seconds
- Any action resets both clocks, which is what stops an up and a down trading places on consecutive ticks
- The third run is longer because the first attempt ended while the load was still running, so it showed the rise and not the fall
- That longer run also exposed the reaper destroying every idle honeypot at once and taking the fleet to zero. The live floor is now the reapers business and a scale down takes one honeypot, mirroring a scale up promoting one
- Three ticks are missing from the third run. The loop is synchronous and a slow teardown or a busy host costs a beat. Not chased
- Every container in the first run was created and destroyed without one attacker connection reaching it

## what the orchestrator work does and does not show

| claim | state |
|---|---|
| load driven scaling works end to end | partly. count follows load, binding an attacker to a scaled honeypot still happens in the data plane rather than the loop |
| no dropped sessions | the reaper refuses a honeypot holding a session and affinity holds it past the grace, both tested. no run has had a session in flight through an orchestrator scale event |
| no lost logs | yes. drain then copy then verify byte for byte, tty recordings included |
| cold start shown failing then fixed | latency measured either side. the connection loss it was expected to cause was never reproduced on this topology |
| affinity shown failing then fixed | no. affinity was built and tested, not observed failing first |
| flapping shown failing then fixed | yes. same seeded load, 14 reversals to 3 to 0, 11 containers to 4 |
| demo recorded | yes, `docs/evidence/demo.cast` |

- Two of those gaps are the same gap. The decoy absorbs anything the redirect does not claim, so a slow or missing scale up mis-serves an attacker here rather than dropping one
- Closing the first row means moving registration into the loop, which is a design change rather than a fix

## scalability

Hardened honeypots, monitoring stack stopped unless stated. Raw output in `docs/evidence/`.

### trigger to ready

| path | n | median | range |
|---|---|---|---|
| create, stack down | 20 | 4.02 s | 3.13 to 5.31 s |
| create, stack up | 8 of 9 | 17.14 s | 12.18 to 21.00 s |
| create on the tick | 8 | 3.90 s | 2.98 to 4.80 s |
| promote on the tick | 8 | 2 µs | 1 to 2 µs |

- `cmd/coldstart` and the orchestrate `took_us` column
- Hardening did not slow a create, mean 3.97 s against 6.27 s before
- Stack up: one sample missed the 60 s timeout. Grafana at 273 to 307% CPU still loading plugins, soon after boot

### step response

`PROFILE=step ROUNDS=12`, 5 s tick.

| run | ups | peak live | back to 1 |
|---|---|---|---|
| warm pool | 8 | 9 | 270 s |
| create on demand | 8 | 9 | 260 s |

- First up on the first loaded tick
- Up never converges. Nothing binds the attacker so the fleet grows a honeypot a tick
- Down converges at one per cooldown, about 33 s a honeypot
- Two ticks dropped during a warm run scale down

### max concurrent

`cmd/pool -n 5 -keep` until a create failed or free memory fell under 1 GiB.

- 80 ran, the next batch missed the readiness timeout
- Churn binds, not memory. Load 240 and 43% CPU pressure in `/proc/pressure`, docker hung, VM reset
- 80 idle: load 11.9, 0.4% CPU pressure
- Memory alone allows about 208

### per instance

| measure | value |
|---|---|
| memory idle | 42.2 MiB, 46.5 MiB host side |
| cpu idle | 0 |
| cpu per attack session | 40 ms |

- `docker stats` across 10, the ap-cowrie cgroup `usage_usec` over one `creds.sh` run
- About 12 sessions a second per honeypot at the 0.5 CPU cap, derived

### redirect latency

TCP connect time from the attacker, 4 runs of 200 each way. `scripts/connect-timing.sh`

| path | run medians |
|---|---|
| direct | 2445 to 2544 µs |
| redirect | 2501 to 2536 µs |

- 15 µs apart, inside the 99 µs spread between direct runs. Not resolvable

### throughput

Not measured. Honeypot traffic is handshakes and short shells, a bulk figure would measure VirtualBox.

## fidelity

Cowrie against the defender's own sshd, probed from the attacker. Raw output in `docs/evidence/fidelity-*.txt` and `affinity.txt`.

| vector | tells | evidence |
|---|---|---|
| banner | no | claims OpenSSH 9.2p1 Debian 12, matching its `uname`, `debian_version` and `ssh -V` |
| offered algorithms | yes | offers CBC, 3DES, CAST, HMAC-MD5, plain zlib, group14-sha1 and SHA-1 `ssh-rsa`. Lacks chacha20, GCM, etm MACs, sntrup761 and strict kex. No OpenSSH 9.2 offers that set |
| auth methods | no | publickey and password on both |
| garbage first line | no | both reply `Invalid SSH identification string.` |
| recon commands | yes | `ip`, `ss`, `systemctl`, `journalctl` not found. `df`, `lsblk` exec format error. `/etc/os-release` empty |
| state across logins | yes | a file written in one login is gone at the next |
| host key at the handoff | yes | the decoy address shows ap-cowrie's key, then the bound honeypot's once redirected |
| affinity | no | same key and every session on one honeypot across a scale up and a scale down |
| redirect latency | no | 15 µs against a 99 µs run spread, see scalability |

- Only tells no OpenSSH release would show count. The baseline is OpenSSH 10.2p1, newer than the claim
- Algorithms: config can drop the legacy set but cant add what Twisted lacks, so it narrows the tell without closing it
- Host key: each honeypot generates its own. A source that touched the decoy before being flagged meets a changed key after, and stock ssh refuses to connect. One key set shared across the fleet would close it
