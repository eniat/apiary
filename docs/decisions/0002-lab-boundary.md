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