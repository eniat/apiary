# containment

Boundary as built: defender and attacker on an isolated host-only segment, no gateway on either lab interface. Attacker has no NAT adapter at all. Defender's NAT adapter is disconnected except when pulling images or pushing commits.

Raw transcript in `docs/evidence/containment-battery.txt`.

| from | to | expected | result |
|---|---|---|---|
| attacker | 10.10.10.10 defender | reach | reached |
| attacker | 10.10.10.1 host | on-segment | no ICMP reply, host firewall |
| attacker | 8.8.8.8 | fail | network unreachable |
| attacker | 1.1.1.1 | fail | network unreachable |
| attacker | example.com | fail | no resolution |
| container on apiary-net | example.com | fail | no egress |

The host sits on the lab segment because host-only networking puts it there, though it drops ICMP so ping gets no reply. Accepted in 0002, and the reason egress rules block the management interface explicitly rather than leaning on topology.

## from inside a honeypot

Driven by `scripts/test-egress.sh`, `test-escape.sh` and `test-limits.sh`. Raw output in `docs/evidence/egress-battery.txt`, `escape-battery.txt` and `limits-battery.txt`.

| class | attempt | control | result |
|---|---|---|---|
| egress | 8.8.8.8:53, 1.1.1.1:443 | DOCKER-USER drop | timed out, no route with the cable out |
| egress | example.com | no resolver path | no resolution in either cable state |
| egress | 10.0.0.1, 172.16.0.1, 192.168.1.1 | DOCKER-USER drop | timed out |
| egress | bridge gateway, defender, host, attacker | INPUT and DOCKER-USER drop | timed out |
| egress | another honeypot on the bridge | none | reached |
| escape | docker socket | never mounted | absent |
| escape | capabilities | cap drop all | CapEff empty |
| escape | write the rootfs | read only rootfs | read only filesystem |
| escape | redirect map | no bpffs or CAP_BPF | not visible |
| escape | raw socket | no CAP_NET_RAW, apparmor | permission denied |
| escape | syscall outside the profile | seccomp | EPERM |
| escape | mount proc | seccomp, no CAP_SYS_ADMIN | EPERM |
| escape | docker api on the gateway | INPUT drop | timed out |
| escape | kernel exploit | none | not attempted, the VM is the boundary |
| exhaustion | four busy processes | cpu.max 0.5 | capped, 0.22 CPU used |
| exhaustion | allocate until killed | memory.max 256 MiB, no swap | OOM killed at 208 MiB |
| exhaustion | fork until refused | pids.max 128 | refused after 126 forks |
| exhaustion | disk io | blkio weight 500 | not testable, a share not a cap |

- Egress drops are by rule, both DROP counters advanced on every run
- Honeypot to honeypot stays open because `br_netfilter` breaks the redirect, see 0002
- Exhaustion rows read the cgroup's own counters, and the honeypot still answered afterwards
- Every inside probe goes through `docker exec`, the same confinement but not the attacker's path, since cowrie's shell runs no real binary
- Controls are layered, so some refusals have more than one cause
- The write probe targets a world writable path, so it tests the mount and not file ownership
