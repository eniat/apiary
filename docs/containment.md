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


## egress from a honeypot

Driven by `scripts/test-egress.sh`, raw transcript of both cable states in `docs/evidence/egress-battery.txt`.

| from | to | expected | result |
|---|---|---|---|
| honeypot | own loopback 2222 | reach | reached, the probe's control |
| honeypot | 8.8.8.8:53 | fail | timed out |
| honeypot | 1.1.1.1:443 | fail | timed out |
| honeypot | example.com:80 | fail | no resolution |
| honeypot | 10.0.0.1:22 | fail | timed out |
| honeypot | 172.16.0.1:22 | fail | timed out |
| honeypot | 192.168.1.1:80 | fail | timed out |
| honeypot | 172.30.0.1:22 bridge gateway | fail | timed out |
| honeypot | 10.10.10.10:22 defender | fail | timed out |
| honeypot | 10.10.10.1:445 host | fail | timed out |
| honeypot | 10.10.10.20:22 attacker | fail | timed out |
| honeypot | another honeypot 445 | fail | reached |

Destinations off the box traverse DOCKER-USER, the defender's own addresses traverse INPUT, and both DROP counters advanced on every run, so these are refusals by rule and not by routing. The internet rows are the evidence: with the NAT cable out they fail with no route, with it in they time out against the rule.

Name resolution fails in both cable states, so docker's embedded resolver is not an egress path around the rules.

The one success is honeypot to honeypot on the shared bridge, which 0002 records and explains.
