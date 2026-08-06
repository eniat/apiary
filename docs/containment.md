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

Egress rules are not yet in place, so this measures the topology alone. Per-destination allowlist testing comes later.
