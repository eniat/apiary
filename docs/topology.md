# topology

    attacker VM                        defender VM
    10.10.10.20                        10.10.10.10
    enp0s8  ─────── host-only ───────  enp0s8
                    10.10.10.0/24         │
                    no gateway            │ nat PREROUTING, DOCKER chain
                                          │ dpt:2222 -> 172.30.0.3:2222
                                          ▼
                                    br-966d540a64b4
                                    172.30.0.1/16
                                       │        │
                              vethXXXXXXX    vethXXXXXXX   <-- TC hook attaches here
                                       │        │
                                    eth0     eth0
                              172.30.0.3   172.30.0.2
                               ap-cowrie   ap-dionaea
                                    2222        445

- bridge name is `br-` plus the apiary-net id prefix printed by `make iface`
- veth names, container addresses and MACs are reassigned on every restart. Meaning they are resolved at registration rather than written down
- `docker0` exists but is DOWN with nothing attached. Attaching there sees zero packets
- `enp0s3` is the defender's NAT adapter. Disconnected except for fetching
- rule detail in `packet-path.md`
