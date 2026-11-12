# 0002: lab boundary and threat model

**Defending against:** compromised honeypot pivoting to other hosts, exhausting host resources or attacking third parties.

**Not defending against:** kernel 0-day escape. Everything runs in a disposable VM I can roll back so it is accepted.

**Boundary as built**
- Two VirtualBox VMs on an isolated host-only segment, 10.10.10.0/24, DHCP off
- Defender 10.10.10.10, attacker 10.10.10.20, topology in `lab-setup.md`
- Neither lab interface has a gateway, the attacker has no NAT adapter at all
- Defender keeps a NAT adapter for image pulls and pushes, disconnected otherwise
- No port forward reaches any honeypot port, so nothing outside the segment reaches a container
- Attacker traffic stays on the segment, generated locally

**Accepted gap:** the host sits on the host-only segment on 10.10.10.1, so it is reachable from the lab in principle. It drops ICMP today, and egress rules will block the management interface explicitly rather than leaning on topology to hide it.

**Kill switch**
- Guest: `ip link set enp0s8 down`
- Host: `VBoxManage controlvm apiary-defender setlinkstate1 off`

Containment demonstrated from the attacker and from a container on apiary-net, transcript in `docs/evidence/containment-battery.txt`. Egress allowlist testing comes once the rules are in place.
**Escape vectors**

Namespaces decide what a container sees, cgroups what it consumes, capabilities and seccomp and LSMs what it may do. The kernel is shared so a kernel bug is an escape, already accepted above.

In place today: no socket mounted, no privileged flag, no gateway on either lab interface. The rest is planned and the test is what proves it.

| vector | mitigation | test |
|---|---|---|
| docker socket mounted in | never mounted, two binds and neither is it | look for it inside, inspect the binds |
| privileged container | never used | inspect reports privileged false |
| excessive capabilities, CAP_SYS_ADMIN above all | drop all, add back only what cowrie needs | capsh print shows the reduced set, a privileged op fails |
| writable host mounts | read only rootfs, writes only to the two binds and declared tmpfs | write outside them and it fails |
| container root is host root | not implemented, the attacker facing process already runs unprivileged | not tested, see the note below |
| exhausting host cpu memory pids io | cgroup limit on each | stress each from inside, host stays responsive |
| pivot to another host or a third party | default deny egress in DOCKER-USER, narrow allowlist | a battery row per destination |
| reaching the management interface | blocked explicitly, not hidden by topology | from a container, the host address on the lab segment |
| poisoning the log pipeline through the log bind | collector mounts it read only on its own bridge, store unreachable from apiary-net, schema nests the original event | write a crafted line into a honeypot log, it arrives as a record without touching labels |
| writing the redirect map | pins need CAP_BPF and bpffs, a honeypot has neither | attempt a map write from inside |
| kernel exploit | none | not tested, accepted. disposable VM |

**On user namespace remapping.** Not implemented. It is daemon wide, so it relocates the image store and shifts the uid behind every bind mount. The provisioner's chown of each log directory would then land on the wrong owner and cowrie fails silently on every write, taking session counts, attribution and the archive with it. The process an attacker reaches already has an unprivileged uid, no capabilities, a read only rootfs, a seccomp allowlist and an apparmor profile, so remapping changes where a kernel escape lands rather than whether one is possible, and that risk is accepted above.
