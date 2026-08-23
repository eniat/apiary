# packet path

Attacker to honeypot process with the rules as they exist on the defender.

## hops

- attacker sends to `10.10.10.10:2222` arrives on `enp0s8`
- nat PREROUTING jumps to DOCKER which rewrites the destination
- routed onto the `apiary-net` bridge out the host-side veth
- emerges as `eth0` in the container netns

## the rules

    DNAT tcp -- !br-966d540a64b4 tcp dpt:2222 to:172.30.0.3:2222
    MASQUERADE all -- !br-966d540a64b4 172.30.0.0/16
    DOCKER-USER: ACCEPT all -- 10.10.10.0/24 -> 172.30.0.0/16

- the DNAT line is why `ssh -p 2222` reaches Cowrie, `!br-` stops containers hairpinning through it
- counters confirm it. DNAT fires once per connection, DOCKER-USER sees every packet
- MASQUERADE is container-initiated outbound only, replies here are un-NATed by conntrack
- DOCKER-USER is the chain Docker will not overwrite, where the egress allowlist goes

## for the dataplane

- the attacker source survives untouched to the container, which is what makes a source-keyed redirect map viable
- DNAT pins a port to one container the redirect chooses per packet instead
- attach at the host-side veth not `docker0` which is down and unused
- bridge name is `br-` plus the network id prefix, veths, addresses and MACs are reassigned every restart. Read at registration and never cache
