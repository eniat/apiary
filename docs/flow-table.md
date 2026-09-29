# flow table

| direction | hook | map | action |
|---|---|---|---|
| attacker to decoy | bridge egress | `flow_fwd` | rewrite dst and redirect to the honeypot veth |
| honeypot to attacker | bridge ingress | `flow_rev` | rewrite src back to the decoy |

- Both entries are written on a SYN from a source in `redirect_targets`. No entry means the segment passes untouched
- `flow_fwd` holds a copy of the target so remapping a source never moves a live flow
- Egress runs after netfilter and ingress before it so host conntrack only sees attacker and decoy
- Decoys must be live addresses. Dark ones never reach the bridge

## key

Exact tuple per direction: saddr daddr sport dport proto. Network order with padding zeroed since keys compare as raw bytes. One shared key cant work as only the forward packet carries the decoy address.

| map | key | value |
|---|---|---|
| `flow_fwd` | `10.10.10.20:46320 > 172.30.0.2:2222` | honeypot 172.30.0.3 with ifindex and MAC |
| `flow_rev` | `172.30.0.3:2222 > 10.10.10.20:46320` | decoy 172.30.0.2 |

## expiry

- LRU hashes of 8192 rows
- Last seen ns updated on every hit. Idle over 120s counts as a miss and is deleted
- No FIN or RST tracking
