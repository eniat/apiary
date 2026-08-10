# lab topology

Two VMs on a VirtualBox host-only segment. The defender runs Docker, the
honeypots, and the data plane. The attacker runs recon and brute-force tooling.
The segment has no gateway and no route off it.

Addresses are static because the data plane later hardcodes the attacker address
into a BPF map and it has to survive reboots rather than track DHCP.

| host     | interface | address         | role                         |
|----------|-----------|-----------------|------------------------------|
| defender | enp0s8    | 10.10.10.10/24  | docker, honeypots, dataplane |
| attacker | enp0s8    | 10.10.10.20/24  | nmap, hydra, attack scripts  |

- Segment: `10.10.10.0/24`, host-only, DHCP disabled, host sits on 10.10.10.1
- Attacker has no NAT adapter, the host-only interface is its only link and it
  carries no default route
- Defender keeps a NAT adapter for image pulls and pushes, disconnected during
  containment checks, host-only otherwise
- Attacker holds a static route to `172.30.0.0/16` via the defender for the
  decoy subnet, inert until the data plane forwards it
- apiary-net is the Docker bridge, created with an explicit subnet so the range is reserved rather than allocated from Docker's default pool: `docker network create --subnet 172.30.0.0/16 apiary-net`

Reach the defender on 10.10.10.10, the attacker on 10.10.10.20 or from the
defender directly.