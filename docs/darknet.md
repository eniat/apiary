# darknet

| block | use |
|---|---|
| `172.30.0.0/24` | containers |
| `172.30.99.0/24` | dark. Never assigned |
| rest of `172.30.0.0/16` | unused |

- IPAM allocates upward from `172.30.0.2` so it never reaches the dark block. `make check` fails if a container ever holds one
- Attacker reaches the block through its static route to `172.30.0.0/16`
- Dark traffic never crosses the bridge. The defender ARPs for the address, gets no answer and drops the SYN. So the darknet lookup runs on `enp0s8` ingress
